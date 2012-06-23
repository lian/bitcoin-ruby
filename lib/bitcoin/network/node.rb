Bitcoin.require_dependency :eventmachine
Bitcoin.require_dependency :json
require 'fileutils'

module Bitcoin::Network

  class Node

    # configuration hash
    attr_reader :config

    # logger
    attr_reader :log

    # connections to other peers (Array of ConnectionHandler)
    attr_reader :connections

    # command connections (Array of CommandHandler)
    attr_reader :command_connections

    # storage queue (blocks/tx waiting to be stored)
    attr_reader :queue

    # inventory queue (blocks/tx waiting to be downloaded)
    attr_reader :inv_queue

    # inventory cache (blocks/tx recently downloaded)
    attr_reader :inv_cache

    # Bitcoin::Storage backend
    attr_reader :store

    # peer addrs (Array of Bitcoin::Protocol::Addr)
    attr_reader :addrs

    # clients to be notified for new block/tx events
    attr_reader :notifiers

    attr_reader :in_sync

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
      :addr_file => "#{ENV['HOME']}/.bitcoin-ruby/addrs.json",
      :log => {
        :network => :info,
        :storage => :info,
      },
      :max => {
        :connections => 8,
        :addr => 256,
        :queue => 64,
        :inv => 128,
        :inv_cache => 1024,
      },
      :intervals => {
        :queue => 5,
        :inv_queue => 5,
        :addrs => 5,
        :connect => 15,
        :relay => 600,
      },
    }

    def initialize config = {}
      @config = DEFAULT_CONFIG.deep_merge(config)
      @log = Bitcoin::Logger.create(:network, @config[:log][:network])
      @connections = []
      @command_connections = []
      @queue = []
      @queue_thread = nil
      @inv_queue = []
      @inv_queue_thread = nil
      set_store
      load_addrs
      @timers = {}
      @inv_cache = []
      @notifiers = Hash[[:block, :tx, :connection, :addr].map {|n| [n, EM::Channel.new]}]
      @in_sync = false
    end

    def set_store
      backend, config = @config[:storage].split('::')
      @store = Bitcoin::Storage.send(backend, {:db => config}, ->(locator) {
          peer = @connections.select(&:connected?).sample
          peer.send_getblocks(locator)
        })
      @store.log.level = @config[:log][:storage]
    end

    def load_addrs
      unless File.exist?(@config[:addr_file])
        @addrs = []
        return
      end
      @addrs = JSON.load(File.read(@config[:addr_file])).map do |a|
        addr = Bitcoin::P::Addr.new
        addr.time, addr.service, addr.ip, addr.port =
          a['time'], a['service'], a['ip'], a['port']
        addr
      end
      log.info { "Initialized #{@addrs.size} addrs from #{@config[:addr_file]}." }
    end

    def store_addrs
      return  if !@addrs || !@addrs.any?
      file = @config[:addr_file]
      FileUtils.mkdir_p(File.dirname(file))
      File.open(file, 'w') do |f|
        addrs = @addrs.map {|a|
          Hash[[:time, :service, :ip, :port].zip(a.entries)] rescue nil }.compact
        f.write(JSON.pretty_generate(addrs))
      end
      log.info { "Stored #{@addrs.size} addrs to #{file}" }
    rescue
      log.warn { "Error storing addrs to #{file}." }
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
        store_addrs
        log.info { "Bye" }
      end

      init_epoll  if @config[:epoll]

      EM.run do
        [:addrs, :connect, :relay].each do |name|
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

        work_connect if @addrs.any?
        connect_dns  if @config[:dns]
        work_inv_queue
        work_queue
      end
    end

    # connect to peer at given +host+ / +port+
    def connect_peer host, port
      return  if @connections.map{|c| c.host}.include?(host)
      log.info { "Attempting to connect to #{host}:#{port}" }
      EM.connect(host, port.to_i, ConnectionHandler, self, host, port.to_i)
    rescue
      log.warn { "Error connecting to #{host}:#{port}" }
      log.debug { $!.inspect }
    end

    # query addrs from dns seed and connect
    def connect_dns
      unless Bitcoin.network[:dns_seeds].any?
        return log.warn { "No DNS seed nodes available" }
      end
      connect_dns_resolver(Bitcoin.network[:dns_seeds].sample) do |addrs|
        log.debug { "DNS returned addrs: #{addrs.inspect}" }
        addrs.sample(@config[:max][:connections] / 2).uniq.each do |addr|
          connect_peer(addr, Bitcoin.network[:default_port])
        end
      end
    end

    # get peer addrs from given dns +seed+ using em/dns_resolver.
    # fallback to using `nslookup` if it is not installed or fails.
    def connect_dns_resolver(seed)
      if Bitcoin.require_dependency "em/dns_resolver", gem: "em-dns", exit: false
        log.info { "Querying addresses from DNS seed: #{seed}" }

        dns = EM::DnsResolver.resolve(seed)
        dns.callback {|addrs| yield(addrs) }
        dns.errback do |*a|
          log.error { "Cannot resolve DNS seed #{seed}: #{a.inspect}" }
          connect_dns_nslookup(Bitcoin.network[:dns_seeds].sample) {|a| yield(a) }
        end
      else
        log.info { "Falling back to nslookup resolver." }
        connect_dns_nslookup(seed) {|a| yield(a) }
      end
    end

    # get peers from dns via nslookup
    def connect_dns_nslookup(seed)
      log.info { "Querying addresses from DNS seed: #{seed}" }
      addrs = `nslookup #{seed}`.scan(/Address\: (.+)$/).flatten
      #  exit  if @config[:dns] && hosts.size == 0
      yield(addrs)
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

    # query blocks from random peer
    def getblocks locator = store.get_locator
      peer = @connections.select(&:connected?).sample
      return  unless peer
      log.info { "querying blocks from #{peer.host}:#{peer.port}" }
      if @config[:headers_only]
        peer.send_getheaders locator  unless @queue.size >= @config[:max][:queue]
      else
        peer.send_getblocks locator  unless @inv_queue.size >= @config[:max][:inv]
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
      EM.defer(nil, proc { work_queue }) do
        if @queue.size == 0
          getblocks  if @inv_queue.size == 0 && !@in_sync
          sleep @config[:intervals][:queue]
        end
        while obj = @queue.shift
          begin
            if @store.send("store_#{obj[0]}", obj[1])
              if obj[0].to_sym == :block
                block = @store.get_block(obj[1].hash)
                @notifiers[:block].push([obj[1], block.depth])  if block.chain == 0
              else
                @notifiers[:tx].push([obj[1]])
              end
            end
          rescue
            @log.warn { $!.inspect }
            puts *$@
          end
        end
        @in_sync = (@store.get_head && (Time.now - @store.get_head.time).to_i < 3600) ? true : false
      end
    end

    # check for new items in the inv queue and process them,
    # unless the queue is already full
    def work_inv_queue
      EM.defer(nil, proc { work_inv_queue }) do
        sleep @config[:intervals][:inv_queue]  if @inv_queue.size == 0
        @log.debug { "inv queue worker running" }
        if @queue.size >= @config[:max][:queue]
          sleep @config[:intervals][:inv_queue]
        else
          while inv = @inv_queue.shift
            next  if !@in_sync && inv[0] == :tx
            next  if @queue.map{|i|i[1]}.map(&:hash).include?(inv[1])
            # next  if @store.send("has_#{inv[0]}", inv[1])
            inv[2].send("send_getdata_#{inv[0]}", inv[1])
          end
        end
      end
    end

    # queue inv, caching the most current ones
    def queue_inv inv
      @inv_cache.shift(128)  if @inv_cache.size > @config[:max][:inv_cache]
      return  if @inv_cache.include?([inv[0], inv[1]]) ||
        @inv_queue.size >= @config[:max][:inv] ||
        (!@in_sync && inv[0] == :tx)
      @inv_cache << [inv[0], inv[1]]
      @inv_queue << inv
    end


    # initiate epoll with given file descriptor and set effective user
    def init_epoll
      log.info { "EPOLL: Available file descriptors: " +
        EM.set_descriptor_table_size(@config[:epoll_limit]).to_s }
      if @config[:epoll_user]
        EM.set_effective_user(@config[:epoll_user])
        log.info { "EPOLL: Effective user set to: #{@config[:epoll_user]}" }
      end
      EM.epoll
    end

    def relay_tx(tx)
      return false  unless @in_sync
      @store.store_tx(tx)
      @connections.select(&:connected?).sample((@connections.size / 2) + 1).each do |peer|
        peer.send_inv(:tx, tx)
      end
    end

    def work_relay
      log.debug { "relay worker running" }
      @store.get_unconfirmed_tx.each do |tx|
        log.info { "relaying tx #{tx.hash}" }
        relay_tx(tx)
      end
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
