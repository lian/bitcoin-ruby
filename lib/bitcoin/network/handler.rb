require 'eventmachine'

module Bitcoin::Network

  class Handler < EM::Connection

    include Bitcoin
    include Bitcoin::Storage

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end

    def log; @node.log; end

    def initialize node, host, port
      @node, @host, @port = node, host, port
      @parser = Bitcoin::Protocol::Parser.new(self)
      @state = :new
    end

    def post_init
      log.info { "Connected to #{@host}:#{@port}" }
      @state = :established
      @node.connections << self
      on_handshake_begin
    end

    def receive_data data
      log.debug { "Receiving data (#{data.size} bytes)" }
      @parser.parse(data)
    end

    def unbind
      log.info { "Disconnected #{@host}:#{@port}" }
      @state = :disconnected
      @node.connections.delete(self)
    end


    def on_inv_transaction(hash)
      log.info { ">> inv transaction: #{hth(hash)}" }
      pkt = Protocol.getdata_pkt(:tx, [hash])
      log.info { "<< getdata tx: #{hth(hash)}" }
      send_data(pkt)
    end

    def on_inv_block(hash)
      log.info { ">> inv block: #{hth(hash)}" }
      pkt = Protocol.getdata_pkt(:block, [hash])
      log.info { "<< getdata block: #{hth(hash)}" }
      send_data(pkt)
    end

    def on_get_transaction(hash)
      log.info { ">> get transaction: #{hth(hash)}" }
    end

    def on_get_block(hash)
      log.info { ">> get block: #{hth(hash)}" }
    end

    def on_addr(addr)
      log.info { ">> addr: #{addr} #{addr.alive?}" }
    end

    def on_tx(tx)
      log.info { ">> tx: #{tx.hash} (#{tx.payload.size} bytes)xs" }
    end

    def on_block(blk)
      log.info { ">> block: #{blk.hash} (#{blk.payload.size} bytes)" }
      #log.info { block.payload.each_byte.map{|i| "%02x" % [i] }.join(" ")
#      puts block.to_json
#      block = Block.from_protocol(blk)
      @node.queue << blk
    end

    def on_version(version)
      log.info { ">> version: #{version.inspect}" }

      @node.block = version.block # temp..

      log.info { "<< verack" }
      send_data( Protocol.verack_pkt )
      
      on_handshake_complete
    end

    def on_verack
      log.info { ">> verack" }
      on_handshake_complete  if @state == :handshake
    end

    def on_handshake_complete
      log.debug { "handshake complete" }
      @state = :connected
      query_blocks
    end

    def query_blocks
      locator = BlockChain.locator
      pkt = Protocol.pkt("getblocks", [Bitcoin::network[:magic_head],
          locator.size.chr, *locator.map{|l| htb(l).reverse}, "\x00"*32].join)
      log.info { "<< getblocks: #{locator.first}" }
      send_data(pkt)
    end

    def on_handshake_begin
      @state = :handshake
      block   = Bitcoin::Storage::BlockChain.depth
      from    = "127.0.0.1:8333"
      from_id = Bitcoin::Protocol::Uniq
      to      = "#{@node.host}:#{@node.port}"
      # p "==", from_id, from, to, block
      pkt = Protocol.version_pkt(from_id, from, to, block)
      log.info { "<< version (#{Bitcoin::Protocol::VERSION})" }
      send_data(pkt)
    end

  end

end
