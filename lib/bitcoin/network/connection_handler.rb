require 'eventmachine'

module Bitcoin::Network

  class ConnectionHandler < EM::Connection

    include Bitcoin
    include Bitcoin::Storage

    attr_reader :host, :port, :state, :version

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end

    def log
      @log ||= Logger::LogWrapper.new("#@host:#@port", @node.log)
    end

    def initialize node, host, port
      @node, @host, @port = node, host, port
      @parser = Bitcoin::Protocol::Parser.new(self)
      @state = :new
      @version = nil
    rescue Exception
      log.fatal { "Error in #initialize" }
      p $!; puts $@; exit
    end

    def post_init
      log.info { "Connected to #{@host}:#{@port}" }
      @state = :established
      @node.connections << self
      on_handshake_begin
    rescue Exception
      log.fatal { "Error in #post_init" }
      p $!; puts $@; exit
    end

    def receive_data data
      log.debug { "Receiving data (#{data.size} bytes)" }
      @parser.parse(data)
    end

    def unbind
      log.info { "Disconnected #{@host}:#{@port}" }
      @state = :disconnected
      @node.connections.delete(self)
      addr = @node.addrs.find{|a|a.ip == @host && a.port == @port}
      @node.addrs.delete(addr)
    end


    def on_inv_transaction(hash)
      log.info { ">> inv transaction: #{hth(hash)}" }
      return  if @node.inv_queue.size > 5000
      unless @node.inv_queue.size >= @node.config[:max][:inv]
        @node.inv_queue << [:tx, hash, self]
      end
    end

    def on_inv_block(hash)
      log.info { ">> inv block: #{hth(hash)}" }
      return  if @node.inv_queue.size > 5000
      unless @node.inv_queue.size >= @node.config[:max][:inv]
        @node.inv_queue << [:block, hash, self]
      end
    end

    def on_get_transaction(hash)
      log.info { ">> get transaction: #{hth(hash)}" }
    end

    def on_get_block(hash)
      log.info { ">> get block: #{hth(hash)}" }
    end

    def on_addr(addr)
      log.info { ">> addr: #{addr.ip}:#{addr.port} alive: #{addr.alive?}, service: #{addr.service}" }
      @node.addrs << addr
    end

    def on_tx(tx)
      log.info { ">> tx: #{tx.hash} (#{tx.payload.size} bytes)" }
      @node.queue.push([:tx, tx])
    end

    def on_block(blk)
      log.info { ">> block: #{blk.hash} (#{blk.payload.size} bytes)" }
      @node.queue.push([:block, blk])
    end

    def on_version(version)
      log.info { ">> version: #{version.version}" }
      @version = version
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
      #send_getaddr
    end


    def send_getdata_tx(hash)
      pkt = Protocol.getdata_pkt(:tx, [hash])
      log.info { "<< getdata tx: #{hth(hash)}" }
      send_data(pkt)
    end

    def send_getdata_block(hash)
      pkt = Protocol.getdata_pkt(:block, [hash])
      log.info { "<< getdata block: #{hth(hash)}" }
      send_data(pkt)
    end

    def send_getblocks
      return get_genesis_block  if @node.store.get_depth == -1
      locator = @node.store.get_locator
      pkt = Protocol.pkt("getblocks", [Bitcoin::network[:magic_head],
          locator.size.chr, *locator.map{|l| htb(l).reverse}, "\x00"*32].join)
      log.info { "<< getblocks: #{locator.first}" }
      send_data(pkt)
    end

    def send_getaddr
      log.info { "<< getaddr" }
      send_data(Protocol.pkt("getaddr", ""))
    end

    def get_genesis_block
      log.info { "Asking for genesis block" }
      pkt = Protocol.getdata_pkt(:block, [htb(Bitcoin::network[:genesis_hash])])
      send_data(pkt)
    end

    def on_handshake_begin
      @state = :handshake
      block   = @node.store.get_depth
      from    = "127.0.0.1:8333"
      from_id = Bitcoin::Protocol::Uniq
      to      = @node.config[:listen].join(':')

      pkt = Protocol.version_pkt(from_id, from, to, block)
      log.info { "<< version (#{Bitcoin::Protocol::VERSION})" }
      send_data(pkt)
    end

    [:new, :handshake, :connected].each do |state|
      define_method("#{state}?") { @state == state }
    end

  end

end
