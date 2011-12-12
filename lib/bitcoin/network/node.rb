require 'eventmachine'

module Bitcoin::Network

  class Node

    attr_reader :config, :log, :connections, :queue, :inv_queue, :store, :addrs
    attr_accessor :block
    
    DEFAULT_CONFIG = {
      :listen => ["0.0.0.0", Bitcoin.network[:default_port]],
      :storage => Bitcoin::Storage.dummy({}),
      :max_connections => 8,
      :connect => [],
    }

    def initialize config = {}
      @config = DEFAULT_CONFIG.merge(config)
      @log = Bitcoin::Logger.create("network")
      @log.level = 0
      @connections = []
      @queue = []
      @queue_thread = nil
      @inv_queue = []
      @inv_queue_thread = nil
      @store = @config.delete(:storage)
      @store.log.level = 0
      @addrs = []
      @timers = {}
    end

    def stop
      log.info { "Shutting down..." }
      EM.stop
    end

    def run
      EM.add_shutdown_hook{
        log.info { "Bye" }
      }

      EM.run{
        {
          :work_queue => 5,
          :work_inv_queue => 5,
          :work_getblocks => 5,
          :work_query_addrs => 30,
          :work_connect => 15,
          :work_cleanup_addrs => 15,
        }.each do |timer, interval|
          @timers[timer] = EM.add_periodic_timer(interval, method(timer))
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
      }
    end

    def connect_peer host, port
      log.info { "Attempting to connect to #{host}:#{port}" }
      EM.connect(host, port.to_i, ConnectionHandler, self, host, port.to_i)
    rescue
      p $!; puts $@; exit
    end

    def connect_dns
      begin
        require 'em/dns_resolver'
      rescue LoadError
        log.warn { "DNS resolver not installed. Either install it or disable DNS seeds with --nd." }
        log.info { "To install DNS resolver run: `gem install em-dns`" }
        exit  if @config[:dns]
      end

      seed = Bitcoin.network[:dns_seeds].sample
      unless seed
        log.warn { "No DNS seed nodes available" }
        return
      end

      log.debug { "Connecting peers from DNS seed: #{seed}" }
      dns = EM::DnsResolver.resolve(seed)
      dns.callback do |addrs|
        log.debug { "DNS returned addrs: #{addrs.inspect}" }
        addrs.sample(@config[:max_connections] / 2).each do |addr|
          connect_peer(addr, Bitcoin.network[:default_port])
        end
      end
      dns.errback do |*a|
        log.error { "Cannot resolve DNS seed #{host}: #{a.inspect}" }
      end
    end

    def work_connect
      log.debug { "Connect worker running" }
      desired = @config[:max_connections] - @connections.size
      return  if desired <= 0
      desired = 32  if desired > 32 # connect to max 32 peers at once
      addrs = @addrs.reject do |addr|
        @connections.map{|c| [c.host, c.port]}.include?([addr.ip, addr.port])
      end
      if addrs.any?
        addrs.sample(desired).each{|addr| connect_peer(addr.ip, addr.port) }
      elsif @config[:dns]
        connect_dns
      end
    rescue
      log.error { "Error during connect" }
    end

    def work_getblocks
      return  unless @connections.select(&:connected?).any?
      blocks = @connections.map(&:version).compact.map(&:block)
      return  unless blocks.any?
      if @store.get_depth >= blocks.inject{|a,b| a+=b;a} / blocks.size
        @timers[:work_getblocks].interval = 30
      end

      log.info { "Querying blocks" }
      if @inv_queue.size < @config[:max_inv]
        @connections.select(&:connected?).sample.send_getblocks
      end
    end

    def work_query_addrs
      return  if !@connections.any? || @config[:max_connections] <= @connections.size
      connections = @connections.select(&:connected?)
      return  unless connections.any?
      connections.sample.send_getaddr
    end

    def work_queue
      @log.debug { "queue worker running" }
      return  if @queue_thread && @queue_thread.alive?
      EM.next_tick do
        @queue_thread = Thread.start do
          begin
            while obj = @queue.shift
              @log.debug { "storing #{obj[0]} #{obj[1].hash} (#{obj[1].payload.bytesize})" }
              @store.send("store_#{obj[0]}", obj[1])
            end
          rescue
            log.error { "Error in queue worker: #{$!}" }
          end
        end
      end
    end

    def work_inv_queue
      return  if @queue.size >= @config[:max_queue]
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

    def work_cleanup_addrs
      return  if @addrs.size < @config[:max_addr]
      log.info { "Cleaning up addrs" }
      @addrs.delete_if{|addr| !addr.alive? }
    end

  end
end
