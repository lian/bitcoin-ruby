require 'eventmachine'

module Bitcoin::Network

  # Node network connection to a peer. Handles all the communication with a specific peer.
  # TODO: incoming/outgoing?
  class ConnectionHandler < EM::Connection

    include Bitcoin
    include Bitcoin::Storage

    attr_reader :host, :port, :state, :version

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end

    def log
      @log ||= Logger::LogWrapper.new("#@host:#@port", @node.log)
    end

    # how long has this connection been open?
    def uptime
      @started ? (Time.now - @started).to_i : 0
    end

    # create connection to +host+:+port+ for given +node+
    def initialize node, host, port
      @node, @host, @port = node, host, port
      @parser = Bitcoin::Protocol::Parser.new(self)
      @state = :new
      @version = nil
      @started = nil
    rescue Exception
      log.fatal { "Error in #initialize" }
      p $!; puts $@; exit
    end

    # check if connection is wanted, begin handshake if it is, disconnect if not
    def post_init
      if @node.connections.size >= @node.config[:max][:connections]
        return close_connection  unless @node.config[:connect].include?([@host, @port.to_s])
      end
      log.info { "Connected to #{@host}:#{@port}" }
      @state = :established
      @node.connections << self
      on_handshake_begin
    rescue Exception
      log.fatal { "Error in #post_init" }
      p $!; puts $@; exit
    end

    # receive data from peer and invoke Protocol::Parser
    def receive_data data
      #log.debug { "Receiving data (#{data.size} bytes)" }
      @parser.parse(data)
    end

    # connection closed; notify listeners and cleanup connection from node
    def unbind
      log.info { "Disconnected #{@host}:#{@port}" }
      @node.notifiers[:connection].push([:disconnected, [@host, @port]])
      @state = :disconnected
      @node.connections.delete(self)
    end

    # received +inv_tx+ message for given +hash+.
    # add to inv_queue, unlesss maximum is reached
    def on_inv_transaction(hash)
      log.debug { ">> inv transaction: #{hth(hash)}" }
      return  if @node.inv_queue.size >= @node.config[:max][:inv]
      @node.queue_inv([:tx, hash, self])
    end

    # received +inv_block+ message for given +hash+.
    # add to inv_queue, unless maximum is reached
    def on_inv_block(hash)
      log.debug { ">> inv block: #{hth(hash)}" }
      return  if @node.inv_queue.size >= @node.config[:max][:inv]
      @node.queue_inv([:block, hash, self])
    end

    # received +get_tx+ message for given +hash+.
    # send specified tx if we have it
    def on_get_transaction(hash)
      log.debug { ">> get transaction: #{hash.unpack("H*")[0]}" }
      tx = @node.store.get_tx(hash.unpack("H*")[0])
      return  unless tx
      pkt = Bitcoin::Protocol.pkt("tx", tx.to_payload)
      log.debug { "<< tx: #{tx.hash}" }
      send_data pkt
    end

    # received +get_block+ message for given +hash+.
    # send specified block if we have it
    # TODO
    def on_get_block(hash)
      log.debug { ">> get block: #{hth(hash)}" }
    end

    # send +inv+ message with given +type+ for given +obj+
    def send_inv type, obj
      pkt = Protocol.inv_pkt(type, [[obj.hash].pack("H*")])
      log.debug { "<< inv #{type}: #{obj.hash}" }
      send_data(pkt)
    end

    # received +addr+ message for given +addr+.
    # store addr in node and notify listeners
    def on_addr(addr)
      log.debug { ">> addr: #{addr.ip}:#{addr.port} alive: #{addr.alive?}, service: #{addr.service}" }
      @node.addrs << addr
      @node.notifiers[:addr].push(addr)
    end

    # received +tx+ message for given +tx+.
    # push tx to storage queue
    def on_tx(tx)
      log.debug { ">> tx: #{tx.hash} (#{tx.payload.size} bytes)" }
      @node.queue.push([:tx, tx])
    end

    # received +block+ message for given +blk+.
    # push block to storage queue
    def on_block(blk)
      log.debug { ">> block: #{blk.hash} (#{blk.payload.size} bytes)" }
      @node.queue.push([:block, blk])
    end

    # received +headers+ message for given +headers+.
    # push each header to storage queue
    def on_headers(headers)
      log.info { ">> headers (#{headers.size})" }
      headers.each {|h| @node.queue.push([:block, h])}
    end

    # received +version+ message for given +version+.
    # send +verack+ message and complete handshake
    def on_version(version)
      log.info { ">> version: #{version.version}" }
      @version = version
      log.info { "<< verack" }
      send_data( Protocol.verack_pkt )
      on_handshake_complete
    end

    # received +verack+ message.
    # complete handshake if it isn't completed already
    def on_verack
      log.info { ">> verack" }
      on_handshake_complete  if handshake?
    end

    # received +alert+ message for given +alert+.
    # TODO: implement alert logic, store, display, relay
    def on_alert(alert)
      log.warn { ">> alert: #{alert.inspect}" }
    end

    # send +getdata tx+ message for given tx +hash+
    def send_getdata_tx(hash)
      pkt = Protocol.getdata_pkt(:tx, [hash])
      log.debug { "<< getdata tx: #{hth(hash)}" }
      send_data(pkt)
    end

    # send +getdata block+ message for given block +hash+
    def send_getdata_block(hash)
      pkt = Protocol.getdata_pkt(:block, [hash])
      log.debug { "<< getdata block: #{hth(hash)}" }
      send_data(pkt)
    end

    # send +getblocks+ message
    def send_getblocks locator = @node.store.get_locator
      return get_genesis_block  if @node.store.get_depth == -1
      pkt = Protocol.pkt("getblocks", [Bitcoin::network[:magic_head],
          locator.size.chr, *locator.map{|l| htb(l).reverse}, "\x00"*32].join)
      log.info { "<< getblocks: #{locator.first}" }
      send_data(pkt)
    end

    # send +getheaders+ message
    def send_getheaders locator = @node.store.get_locator
      return get_genesis_block  if @node.store.get_depth == -1
      pkt = Protocol.pkt("getheaders", [Bitcoin::network[:magic_head],
          locator.size.chr, *locator.map{|l| htb(l).reverse}, "\x00"*32].join)
      log.debug { "<< getheaders: #{locator.first}" }
      send_data(pkt)
    end

    # send +getaddr+ message
    def send_getaddr
      log.debug { "<< getaddr" }
      send_data(Protocol.pkt("getaddr", ""))
    end

    # send +ping+ message
    # TODO: wait for pong and disconnect if it doesn't arrive (and version is new enough)
    def send_ping
      nonce = rand(0xffffffff)
      log.debug { "<< ping (#{nonce})" }
      send_data(Protocol.ping_pkt(nonce))
    end

    # ask for the genesis block
    def get_genesis_block
      log.info { "Asking for genesis block" }
      pkt = Protocol.getdata_pkt(:block, [htb(Bitcoin::network[:genesis_hash])])
      send_data(pkt)
    end

    # complete handshake; set state, started time, notify listeners and add address to Node
    def on_handshake_complete
      return  unless handshake?
      log.debug { "handshake complete" }
      @state = :connected
      @started = Time.now
      @node.notifiers[:connection].push([:connected, info])
      @node.addrs << addr
      # send_getaddr
      # EM.add_periodic_timer(15) { send_ping }
    end

    # received +ping+ message with given +nonce+.
    # send +pong+ message back, if +nonce+ is set.
    # network versions <=60000 don't set the nonce and don't expect a pong.
    def on_ping nonce
      log.debug { ">> ping (#{nonce})" }
      send_data(Protocol.pong_pkt(nonce))  if nonce
    end

    # received +pong+ message with given +nonce+.
    # TODO: see #send_ping
    def on_pong nonce
      log.debug { ">> pong (#{nonce})" }
    end

    # begin handshake; send +version+ message
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

    # get Addr object for this connection
    def addr
      return @addr  if @addr
      @addr = Bitcoin::Protocol::Addr.new
      @addr.time, @addr.service, @addr.ip, @addr.port =
        Time.now.tv_sec, @version.services, @host, @port
      @addr
    end

    [:new, :handshake, :connected].each do |state|
      define_method("#{state}?") { @state == state }
    end

    # get info hash
    def info
      {
        :host => @host, :port => @port, :state => @state,
        :version => @version.version, :block => @version.block, :started => @started.to_i,
        :user_agent => @version.user_agent
      }
    end
  end

end
