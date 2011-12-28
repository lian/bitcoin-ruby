require 'eventmachine'

module Bitcoin::Network

  class Node

    attr_reader :config, :log, :connections, :queue, :inv_queue, :store, :addrs
    attr_accessor :block
    
    DEFAULT_CONFIG = {
      :listen => ["0.0.0.0", Bitcoin.network[:default_port]],
      :connect => [],
      :command => "",
      :storage => Bitcoin::Storage.dummy({}),
      :headers_only => false,
      :dns => true,
      :epoll => false,
      :epoll_limit => 10000,
      :epoll_user => nil,
      :log => {
        :network => :info,
        :storage => :info,
      },
      :max => {
        :connections => 8,
        :addr => 256,
        :queue => 64,
        :inv => 128,
      },
      :intervals => {
        :queue => 5,
        :inv_queue => 5,
        :blocks => 5,
        :addrs => 5,
        :connect => 15,
      },
    }

    def initialize config = {}
      @config = DEFAULT_CONFIG.deep_merge(config)
      @log = Bitcoin::Logger.create("network")
      @log.level = @config[:log][:network]
      @connections = []
      @queue = []
      @queue_thread = nil
      @inv_queue = []
      @inv_queue_thread = nil
      set_store
      @addrs = []
      @timers = {}
    end

    def set_store
      backend, config = @config[:storage].split('::')
      @store = Bitcoin::Storage.send(backend, {:db => config})
      @store.log.level = @config[:log][:storage]
    end

    def stop
      log.info { "Shutting down..." }
      EM.stop
    end

    def uptime
      (Time.now - @started).to_i
    end

    def run
      @started = Time.now

      EM.add_shutdown_hook do
        log.info { "Bye" }
      end

      init_epoll  if @config[:epoll]

      EM.run do
        [:queue, :inv_queue, :blocks, :addrs, :connect].each do |name|
          interval = @config[:intervals][name]
          next  if !interval || interval == 0
          @timers[name] = EM.add_periodic_timer(interval, method("work_#{name}"))
        end

        if @config[:command]
          host, port = @config[:command]
          EM.start_server(host, port, CommandHandler, self)
          log.info { "Command socket listening on #{host}:#{port}" }
        end

        if @config[:listen]
          host, port = @config[:listen]
          EM.start_server(host, port.to_i, ConnectionHandler, self, host, port.to_i)
          log.info { "Server socket listening on #{host}:#{port}" }
        end

        if @config[:connect].any?
          @config[:connect].each{|host| connect_peer(*host) }
        end

        connect_dns  if @config[:dns]
      end
    end

    # connect to peer at given +hosh+ / +port+
    def connect_peer host, port
      return  if @connections.map{|c| c.host}.include?(host)
      log.info { "Attempting to connect to #{host}:#{port}" }
      EM.connect(host, port.to_i, ConnectionHandler, self, host, port.to_i)
    rescue
      p $!; puts $@; exit
    end

    # query addrs from dns seed and connect
    def connect_dns
      require 'em/dns_resolver'

      seed = Bitcoin.network[:dns_seeds].sample
      unless seed
        log.warn { "No DNS seed nodes available" }
        return
      end

      log.info { "Querying addresses from DNS seed: #{seed}" }

      dns = EM::DnsResolver.resolve(seed)
      dns.callback do |addrs|
        log.debug { "DNS returned addrs: #{addrs.inspect}" }
        addrs.sample(@config[:max][:connections] / 2).uniq.each do |addr|
          connect_peer(addr, Bitcoin.network[:default_port])
        end
      end
      dns.errback do |*a|
        log.error { "Cannot resolve DNS seed #{seed}: #{a.inspect}" }
      end

    rescue LoadError
      log.warn { "DNS resolver not installed. Either install it or disable DNS seeds with --nd." }
      log.info { "To install DNS resolver run: `gem install em-dns`" }
      log.info { "DNS resolver fallback to `nslookup ..`" }
      #  exit  if @config[:dns]
      connect_dns_nslookup
    end

    def connect_dns_nslookup
      seed = Bitcoin.network[:dns_seeds].sample
      unless seed
        log.warn { "No DNS seed nodes available" }
        return
      end

      log.info { "Querying addresses from DNS seed: #{seed}" }

      hosts = `nslookup #{seed}`.scan(/Address\: (.+)$/)
                .flatten.sample(@config[:max][:connections] / 2)

      hosts.uniq.each{|addr|
        log.debug { "DNS returned addrs: #{addrs.inspect}" }
        connect_peer(addr, Bitcoin.network[:default_port])
      }
    end

    # check if there are enough connections and try to
    # establish new ones if needed
    def work_connect
      log.debug { "Connect worker running" }
      desired = @config[:max][:connections] - @connections.size
      return  if desired <= 0
      desired = 32  if desired > 32 # connect to max 32 peers at once
      if addrs.any?
        addrs.sample(desired) do |addr|
          Time.now.tv_sec + 10800 - addr.time
        end.each do |addr|
          connect_peer(addr.ip, addr.port)
        end
      elsif @config[:dns]
        connect_dns
      end
    rescue
      log.error { "Error during connect: #{$!.inspect}" }
    end

    # check if the inv queue is running low and issue a
    # getblocks command to a random peer if needed
    def work_blocks
      return  unless @connections.select(&:connected?).any?
      blocks = @connections.map(&:version).compact.map(&:block)
      return  unless blocks.any?
      if @store.get_depth >= blocks.inject{|a,b| a+=b;a} / blocks.size
        @timers[:blocks].interval = 30
      end

      log.info { "Querying blocks" }
      client = @connections.select(&:connected?).sample
      if @config[:headers_only]
        client.send_getheaders  unless @queue.size >= @config[:max][:queue]
      else
        client.send_getblocks  unless @inv_queue.size >= @config[:max][:inv]
      end
    end

    # check if the addr store is full and request new addrs
    # from a random peer if it isn't
    def work_addrs
      log.debug { "addr worker running" }
      @addrs.delete_if{|addr| !addr.alive? }  if @addrs.size >= @config[:max][:addr]
      return  if !@connections.any? || @config[:max][:connections] <= @connections.size
      connections = @connections.select(&:connected?)
      return  unless connections.any?
      log.info { "requesting addrs" }
      connections.sample.send_getaddr
    end

    # check for new items in the queue and process them
    def work_queue
      @log.debug { "queue worker running" }
      return  if @queue_thread && @queue_thread.alive?
      EM.next_tick do
        @queue_thread = Thread.start do
          begin
            while obj = @queue.shift
              @log.debug { "storing #{obj[0]} #{obj[1].hash} (#{obj[1].payload.bytesize})" }
              unless @config[:headers_only] && obj[0] == :tx && obj[1].tx.any?
                @store.send("store_#{obj[0]}", obj[1])
              end
            end
          rescue
            log.error { "Error in queue worker: #{$!}" }
          end
        end
      end
    end

    # check for new items in the inv queue and process them,
    # unless the queue is already full
    def work_inv_queue
      return  if @queue.size >= @config[:max][:queue]
      return  if @inv_queue_thread && @inv_queue_thread.alive?
      @log.debug { "inv_queue worker running" }
      @inv_queue_thread = Thread.start do
        begin
          while inv = @inv_queue.shift
            inv[2].send("send_getdata_#{inv[0]}", inv[1])
          end
        rescue
          log.error { "Error in inv_queue worker: #{$!}" }
        end
      end
    end

    def init_epoll
      log.info { "EPOLL: Available file descriptors: " +
        EM.set_descriptor_table_size(@config[:epoll_limit]).to_s }
      if @config[:epoll_user]
        EM.set_effective_user(@config[:epoll_user])
        log.info { "EPOLL: Effective user set to: #{@config[:epoll_user]}" }
      end
      EM.epoll
    end

  end
end

class Array
  def random(weights=nil)
    return random(map {|n| yield(n) })  if block_given?
    return random(map {|n| n.send(weights) })  if weights.is_a? Symbol

    weights ||= Array.new(length, 1.0)
    total = weights.inject(0.0) {|t,w| t+w}
    point = rand * total

    zip(weights).each do |n,w|
      return n if w >= point
      point -= w
    end
  end

  def weighted_sample(n, weights = nil)
    src = dup
    buf = []
    n = src.size  if n > src.size
    while buf.size < n
      if block_given?
        item = src.random {|n| yield(n) }
      else
        item = src.random(weights)
      end
      buf << item; src.delete(item)
    end
    buf
  end

  class ::Hash
    def deep_merge(hash)
      target = dup
      hash.keys.each do |key|
        if hash[key].is_a? Hash and self[key].is_a? Hash
          target[key] = target[key].deep_merge(hash[key])
          next
        end
        target[key] = hash[key]
      end
      target
    end
  end

end
