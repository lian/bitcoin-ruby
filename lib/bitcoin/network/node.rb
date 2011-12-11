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

    def run
      EM.run do
        {
          :work_queue => 5,
          :work_inv_queue => 5,
          :work_getblocks => 5,
          :work_query_addrs => 30,
          :work_connect => 15
          :work_cleanup_addrs => 15,
        }.each do |timer, interval|
          @timers[timer] = EM.add_periodic_timer(interval) do
            send(timer)
          end
        end

        EM.next_tick do
          begin
            host, port = *@config[:listen]
            EM.start_server host, port.to_i, Handler, self, host, port.to_i
            log.info { "Listening on #{host}:#{port}" }
          rescue
            p $!
            exit 1
          end

          @config[:connect].each do |connect|
            begin
              log.info { "Attempting to connect to #{connect.join(':')}" }
              host, port = *connect
              EM.connect(host, port.to_i, Handler, self, host, port.to_i)
            rescue Exception
              log.error { $!.inspect }
              puts $@
              exit 1
            end
          end
        end
      end
      log.info { "Bye" }
    end

    def work_connect
      desired = @config[:max_connections] - @connections.size
      return  if desired <= 0
      addrs = @addrs.reject do |addr|
        @connections.map{|c| [c.host, c.port]}.include?([addr.ip, addr.port])
      end
      addrs.sample(desired).each do |addr|
        EM.connect(addr.ip, addr.port, Handler, self, addr.ip, addr.port)
      end
    end

    def work_getblocks
      return  unless @connections.any?
      blocks = @connections.map(&:version).compact.map(&:block)
      return  unless blocks.any?
      if @store.get_depth >= blocks.inject{|a,b| a+=b;a} / blocks.size
        @timers[:work_getblocks].interval = 30
      end

      log.info { "Querying blocks" }
      if @inv_queue.size < @config[:max_inv]
        @connections.sample.send_getblocks
      end
    end

    def work_query_addrs
      return  if !@connections.any? || @config[:max_connections] <= @connections.size
      connections = @connections.select{|c| c.state == :connected}
      return  unless connections.any?
      connections.sample.send_getaddr
    end

    def work_queue
      @log.debug { "queue worker running" }
      return  if @queue_thread && @queue_thread.alive?
      @queue_thread = Thread.start do
        begin
          EM.next_tick do
            while obj = @queue.shift
              @log.debug { "storing #{obj[0]} #{obj[1].hash} (#{obj[1].payload.bytesize})" }
              @store.send("store_#{obj[0]}", obj[1])
            end
          end
        rescue
          log.error { "Error in queue worker: #{$!}" }
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
      @addrs.each do |addr|
        @addrs.delete(addr)  unless addr.alive?
      end
    end

  end
end
