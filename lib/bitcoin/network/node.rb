require 'log4r'
require 'eventmachine'

module Bitcoin::Network

  class Node

    attr_reader :host, :port, :log, :connections, :queue, :store
    attr_accessor :block
    
    def initialize
      @log = Log4r::Logger.new("network")
      @log.outputters << Log4r::Outputter.stdout
      @log.level = 2
      @connections = []
      @queue = []
      @block = 0 # temp hack to store block depth of connected node
      @store = Bitcoin::Storage::Backends::Dummy.new
    end

    def run
      EM.run do
        EventMachine::add_periodic_timer(10) { check_query_blocks }
        EventMachine::add_periodic_timer(0.5) { check_queue }
        begin
          log.info { "Attempting to connect to #{@host}:#{@port}" }
          h, p = "127.0.0.1", Bitcoin::network[:default_port]
          EM.connect(h, p, Handler, self, h, p)
        rescue Exception
          log.error { $!.inspect }
          puts $@
          exit 1
        end
        Signal.trap("INT") do
          log.info { "Shutting down..." }
          Signal.trap("INT") do
            log.warn { "Force Exit" }
            exit 1
          end
          EM.stop_event_loop
        end

      end
      log.info { "Bye" }
    end

    def check_query_blocks
      log.debug { "Checking queue" }
      return  unless @connections.any?
      log.info { "Querying blocks" }
      if @queue.size < 128
        @connections[rand(@connections.size)].query_blocks
      end
    end

    def check_queue
      log.debug { "Checking queue" }
      return unless @queue.any?
      while block = @queue.shift
        next  unless block
        log.debug { "Processing queue item #{block.hash} (#{block.payload.size} bytes)" }

        @store.store_block(block)
      end
      check_query_blocks
      log.info { "Queue empty" }
    rescue Exception
      p $!
      puts *$@
      exit 1
    end
  end
  
end
