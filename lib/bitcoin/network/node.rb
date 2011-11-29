require 'log4r'
require 'eventmachine'

module Bitcoin::Network

  class Node

    attr_reader :host, :port, :log, :connections, :queue
    attr_accessor :block
    
    def initialize
      @log = Log4r::Logger.new("network")
      @log.outputters << Log4r::Outputter.stdout
      @log.level = 2
      @connections = []
      @queue = []
      @block = 0
    end

    def run
      EM.run do
        EventMachine::add_periodic_timer(10) { check_query_blocks }
        EventMachine::add_periodic_timer(0.5) { check_queue }
        EventMachine::add_periodic_timer(5) { display_stats }
        begin
          log.info { "Attempting to connect to #{@host}:#{@port}" }
          h, p = "127.0.0.1", Bitcoin::network[:default_port]
          EM.connect(h, p, Handler, self, h, p)
        rescue Exception
          log.error { $!.inspect }
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
      last = Bitcoin::Storage::Block.order("when_found DESC").limit(1).first.when_found
      if @queue.size < 128
        @connections[rand(@connections.size)].query_blocks
      end
    end

    def display_stats
      puts( {:connections => @connections.size, :queue => @queue.size,
              :blocks => Bitcoin::Storage::BlockChain.depth}.inspect )
    end

    def check_queue
      log.debug { "Checking queue" }
      return unless @queue.any?
      while block = @queue.shift
        next  unless block
        log.debug { "Processing queue item #{block.hash} (#{block.payload.size} bytes)" }
        depth = Bitcoin::Storage::BlockChain.add_block(block)
        if (depth >= @block rescue false)
          log.info { "BLOCK CHAIN UP TO DATE: #{depth} blocks" }
        end
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
