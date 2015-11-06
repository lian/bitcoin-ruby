$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'eventmachine'
require 'bitcoin'
require 'socket'

class Bitcoin::Protocol::Parser; def log; stub=Object.new; def stub.method_missing(*a); end; stub; end; end


module SimpleNode
  class Connection < EM::Connection

    def on_ping(nonce)
      send_data(Bitcoin::Protocol.pong_pkt(nonce)) if nonce
    end

    def on_reject(reject)
      log.info { "reject #{reject}" }
    end

    def on_tx(tx)
      log.info { "received transaction: #{tx.hash}" }

      puts tx.to_json

      if tx.hash == @ask_tx
        @args[:result] = tx
        @args[:callback] ? (close_connection; @args[:callback].call(tx)) : EM.stop
      end
    end

    def on_block(block)
      log.info { "received block: #{block.hash}" }

      puts block.to_json

      if block.hash == @ask_block
        if @ask_tx
          if tx = block.tx.find{|tx| tx.hash == @ask_tx }
            on_tx(tx)
          else
            log.info { "@ask_tx #{@ask_tx} not in @ask_block #{@ask_block}" }
            @args[:result] = nil
            @args[:callback] ? (close_connection; @args[:callback].call(nil)) : EM.stop
          end
        else
          @args[:result] = block
          @args[:callback] ? (close_connection; @args[:callback].call(block)) : EM.stop
        end
      end
    end

    def on_handshake_complete
      return if @connected
      @connected = true
      log.info { "handshake complete" }
      
      EM.add_timer(0.5){
        if @ask_block
          log.info { "ask for @ask_block: #{@ask_block}" }
          send_data Bitcoin::Protocol.getdata_pkt(:block, [htb(@ask_block)])
        else
          if @ask_tx
            log.info { "ask for @ask_tx: #{@ask_tx}" }
            send_data Bitcoin::Protocol.getdata_pkt(:tx, [htb(@ask_tx)])
          end
        end
        if @send_tx
          tx = Bitcoin::P::Tx.from_json(File.read(@send_tx))
          send_data(Bitcoin::Protocol.pkt('tx', tx.to_payload))
          p [:sent, tx.hash]
        end
      }
    end

    def on_get_transaction(hash); end
    def on_get_block(hash); end
    def on_addr(addr); end
    def on_inv_transaction(hash)
      log.info { "peer told us about transaction: #{hth(hash)}" }
      log.info { "asking peer for transaction: #{hth(hash)}" }
      send_data Bitcoin::Protocol.getdata_pkt(:tx, [hash])
    end

    def on_inv_block(hash)
      log.info { "peer told us about block: #{hth(hash)}" }
      log.info { "asking peer for block: #{hth(hash)}" }
      send_data Bitcoin::Protocol.getdata_pkt(:block, [hash])
    end

    def on_handshake_begin
      log.info { "handshake started" }

      version = Bitcoin::Protocol::Version.new({
        :user_agent => "/Satoshi:0.8.1/",
        :last_block => 0,
        :from       => "127.0.0.1:#{Bitcoin.network[:default_port]}",
        :to         => "#{@host}:#{@port}",
      })

      log.info { "sending version:  Version:%d (%s)  Block:%d" % version.fields.values_at(:version, :user_agent, :last_block) }
      send_data(version.to_pkt)
    end

    def on_version(version)
      @version ||= version
      log.info { "received version:  Version:%d (%s)  Block:%d" % version.fields.values_at(:version, :user_agent, :last_block) }
      send_data( Bitcoin::Protocol.verack_pkt )
      on_handshake_complete
    end

    def initialize(host, port, node=nil, opts={})
      set_host(host, port)
      @node   = node
      @parser = Bitcoin::Protocol::Parser.new( self )

      @args = opts
      @ask_tx, @ask_block, @send_tx = opts.values_at(:ask_tx, :ask_block, :send_tx)
    end

    def receive_data(data); @parser.parse(data); end
    def post_init; log.info { "peer connected" }; on_handshake_begin; end
    def unbind; log.info { "peer disconnected" }; end
    def set_host(host, port=8333); @host, @port = host, port; end

    def log
      return @log if @log
      return (@log = (stub=Object.new; def stub.method_missing(*a); end; stub)) if @args[:nolog]
      @logger ||= Bitcoin::Logger.create(:network, :info) unless @node.respond_to?(:log)
      @log = Bitcoin::Logger::LogWrapper.new("#@host:#@port", @logger || @node.log)
    end

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end


    def self.connect(host, port, *args)
      EM.connect(host, port, self, host, port, *args)
    end

    def self.connect_random_from_dns(seeds=[], count=1, *args)
      seeds = Bitcoin.network[:dns_seeds] unless seeds.any?
      if seeds.any?
        seeds.sample(count).map{|dns|
          host = IPSocket.getaddress(dns)
          connect(host, Bitcoin.network[:default_port], *args)
        }
      else
        raise "No DNS seeds available. Provide IP, configure seeds, or use different network."
      end
    end

    def self.connect_known_nodes(count=1)
      connect_random_from_dns(Bitcoin.network[:known_nodes], count)
    end
  end
end


if $0 == __FILE__

  args = {
    ask_tx:    ARGV.find{|a| a[/tx=(.+)/, 1] } && $1,
    ask_block: ARGV.find{|a| a[/block=(.+)/, 1] } && $1,
    use_node:  ARGV.find{|a| a[/node=(.+)/, 1] } && $1,
    send_tx:   ARGV.find{|a| a[/send_tx=(.+)/, 1] } && $1,
    set_project:  ARGV.find{|a| a[/project=(.+)/, 1] } && $1,
    callback:  proc{|i|
                 case i
                 when Bitcoin::Protocol::Block
                   puts "INFO  network: SAVING @ask_block: #{i.hash}"
                   File.open("block-#{i.hash}.bin", 'wb'){|f| f.print i.payload }
                   File.open("block-#{i.hash}.json", 'wb'){|f| f.print i.to_json }
                 when Bitcoin::Protocol::Tx
                   puts "INFO  network: SAVING @ask_tx: #{i.hash}"
                   File.open("tx-#{i.hash}.bin", 'wb'){|f| f.print i.payload }
                   File.open("tx-#{i.hash}.json", 'wb'){|f| f.print i.to_json }
                 end
                 EM.stop
               }
  }

  
  EM.run do
    if args[:set_project]
      Bitcoin.network = args[:set_project].to_sym
      p Bitcoin.network_project
    end
    if args[:use_node]
      SimpleNode::Connection.connect_random_from_dns([args[:use_node]], 1, nil, args)
    else
      SimpleNode::Connection.connect_random_from_dns([], 1, nil, args)
    end
  end

end
