# encoding: ascii-8bit

require 'eventmachine'

module Bitcoin::Network

  # Node network connection to a peer. Handles all the communication with a specific peer.
  class ConnectionHandler < EM::Connection

    LATENCY_MAX = (5*60*1000) # 5min in ms

    include Bitcoin
    include Bitcoin::Storage

    attr_reader :host, :port, :version, :direction

    # :new, :handshake, :connected, :disconnected
    attr_reader :state

    # latency of this connection based on last ping/pong
    attr_reader :latency_ms

    def log
      @log ||= Logger::LogWrapper.new("#@host:#@port", @node.log)
    end

    # how long has this connection been open?
    def uptime
      @started ? (Time.now - @started).to_i : 0
    end

    # create connection to +host+:+port+ for given +node+
    def initialize node, host, port, direction
      @node, @host, @port, @direction = node, host, port, direction
      @parser = Bitcoin::Protocol::Parser.new(self)
      @state = :new
      @version = nil
      @started = nil
      @port, @host = *Socket.unpack_sockaddr_in(get_peername)  if get_peername
      @ping_nonce = nil
      @latency_ms = nil
      @lock = Monitor.new
      @last_getblocks = []  # the last few getblocks messages received
    rescue
      log.fatal { "Error in #initialize" }
      p $!; puts $@; exit
    end

    # check if connection is wanted, begin handshake if it is, disconnect if not
    def post_init
      if incoming?
        begin_handshake
      end
    rescue
      log.fatal { "Error in #post_init" }
      p $!; puts *$@
    end

    # only called for outgoing connection
    def connection_completed
      @connection_completed = true
      begin_handshake
    rescue
      log.fatal { "Error in #connection_completed" }
      p $!; puts *$@
    end

    # receive data from peer and invoke Protocol::Parser
    def receive_data data
      #log.debug { "Receiving data (#{data.size} bytes)" }
      @lock.synchronize { @parser.parse(data) }
    rescue
      log.warn { "Error handling data: #{data.hth}" }
      p $!; puts *$@
    end

    # connection closed; notify listeners and cleanup connection from node
    def unbind
      log.info { (outgoing? && !@connection_completed) ? "Connection failed" : "Disconnected" }
      @node.push_notification(:connection, {type: :disconnected, host: @host, port: @port})
      @state = :disconnected
      @node.connections.delete(self)
    end

    # begin handshake
    # TODO: disconnect if we don't complete within a reasonable time
    def begin_handshake
      if incoming? && !@node.accept_connections?
        return close_connection  unless @node.config[:connect].include?([@host, @port.to_s])
      end
      log.info { "Established #{@direction} connection" }
      @node.connections << self
      @state = :handshake
      send_version
    rescue
      log.fatal { "Error in #begin_handshake" }
      p $!; puts *$@
    end

    # complete handshake; set state, started time, notify listeners and add address to Node
    def complete_handshake
      if @state == :handshake
        log.debug { 'Handshake completed' }
        @state = :connected
        @started = Time.now
        @node.push_notification(:connection, info.merge(type: :connected))
        @node.addrs << addr
      end
      send_data P::Addr.pkt(@node.addr)  if @node.config[:announce]
    end

    # received +inv_tx+ message for given +hash+.
    # add to inv_queue, unlesss maximum is reached
    def on_inv_transaction(hash)
      log.debug { ">> inv transaction: #{hash.hth}" }
      if @node.relay_propagation.keys.include?(hash.hth)
        @node.relay_propagation[hash.hth] += 1
      end
      return  if @node.inv_queue.size >= @node.config[:max][:inv]
      @node.queue_inv([:tx, hash, self])
    end

    # received +inv_block+ message for given +hash+.
    # add to inv_queue, unless maximum is reached
    def on_inv_block(hash)
      log.debug { ">> inv block: #{hash.hth}" }
      return  if @node.inv_queue.size >= @node.config[:max][:inv]
      @node.queue_inv([:block, hash, self])
    end

    # received +get_tx+ message for given +hash+.
    # send specified tx if we have it
    def on_get_transaction(hash)
      log.debug { ">> get transaction: #{hash.hth}" }
      tx = @node.store.get_tx(hash.hth)
      tx ||= @node.relay_tx[hash.hth]
      return  unless tx
      pkt = Bitcoin::Protocol.pkt("tx", tx.to_payload)
      log.debug { "<< tx: #{tx.hash}" }
      send_data pkt
    end

    # received +get_block+ message for given +hash+.
    # send specified block if we have it
    def on_get_block(hash)
      log.debug { ">> get block: #{hash.hth}" }
      blk = @node.store.get_block(hash.hth)
      return  unless blk
      pkt = Bitcoin::Protocol.pkt("block", blk.to_payload)
      log.debug { "<< block: #{blk.hash}" }
      send_data pkt
    end

    # received +addr+ message for given +addr+.
    # store addr in node and notify listeners
    def on_addr(addr)
      log.debug { ">> addr: #{addr.ip}:#{addr.port} alive: #{addr.alive?}, service: #{addr.service}" }
      @node.addrs << addr
      @node.push_notification(:addr, addr)
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
      log.debug { ">> version: #{version.version}" }
      @node.external_ips << version.to.split(":")[0]
      @version = version
      log.debug { "<< verack" }
      send_data( Protocol.verack_pkt )

      # sometimes other nodes don't bother to send a verack back,
      # but we can consider the handshake complete once we sent ours.
      # apparently it can happen on incoming and outgoing connections alike
      complete_handshake
    end

    # received +verack+ message.
    # complete handshake if it isn't completed already
    def on_verack
      log.debug { ">> verack" }
      complete_handshake if outgoing?
    end

    # received +alert+ message for given +alert+.
    # TODO: implement alert logic, store, display, relay
    def on_alert(alert)
      log.warn { ">> alert: #{alert.inspect}" }
    end

    # received +getblocks+ message.
    # TODO: locator fallback
    def on_getblocks(version, hashes, stop_hash)
      # remember the last few received getblocks messages and ignore duplicate ones
      # fixes unexplained issue where remote node is bombarding us with the same getblocks
      # message over and over (probably related to missing locator fallback handling)
      return  if @last_getblocks && @last_getblocks.include?([version, hashes, stop_hash])
      @last_getblocks << [version, hashes, stop_hash]
      @last_getblocks.shift  if @last_getblocks.size > 3

      blk = @node.store.db[:blk][hash: hashes[0].htb.blob]
      depth = blk[:depth]  if blk
      log.info { ">> getblocks #{hashes[0]} (#{depth || 'unknown'})" }

      return  unless depth && depth <= @node.store.get_depth
      range = (depth+1..depth+500)
      blocks = @node.store.db[:blk].where(chain: 0, depth: range).order(:depth).select(:hash).all
      send_inv(:block, *blocks.map {|b| b[:hash].hth })
    end

    # received +getaddr+ message.
    # send +addr+ message with peer addresses back.
    def on_getaddr
      addrs = @node.config[:announce] ? [@node.addr] : []
      addrs += @node.addrs.select{|a| a.time > Time.now.to_i - 10800 }.shuffle[0..250]
      log.debug { "<< addr (#{addrs.size})" }
      send_data P::Addr.pkt(*addrs)
    end

    # begin handshake; send +version+ message
    def send_version
      from = "#{@node.external_ip}:#{@node.config[:listen][1]}"
      version = Bitcoin::Protocol::Version.new({
        :version    => 70001,
        :last_block => @node.store.get_depth,
        :from       => from,
        :to         => @host,
        :user_agent => "/bitcoin-ruby:#{Bitcoin::VERSION}/",
        #:user_agent => "/Satoshi:0.8.3/",
      })
      send_data(version.to_pkt)
      log.debug { "<< version: #{Bitcoin.network[:protocol_version]}" }
    end

    # send +inv+ message with given +type+ for given +obj+
    def send_inv type, *hashes
      hashes.each_slice(251) do |slice|
        pkt = Protocol.inv_pkt(type, slice.map(&:htb))
        log.debug { "<< inv #{type}: #{slice[0][0..16]}" + (slice.size > 1 ? "..#{slice[-1][0..16]}" : "") }
        send_data(pkt)
      end
    end

    # send +getdata tx+ message for given tx +hash+
    def send_getdata_tx(hash)
      pkt = Protocol.getdata_pkt(:tx, [hash])
      log.debug { "<< getdata tx: #{hash.hth}" }
      send_data(pkt)
    end

    # send +getdata block+ message for given block +hash+
    def send_getdata_block(hash)
      pkt = Protocol.getdata_pkt(:block, [hash])
      log.debug { "<< getdata block: #{hash.hth}" }
      send_data(pkt)
    end

    # send +getblocks+ message
    def send_getblocks locator = @node.store.get_locator
      if @node.store.get_depth == -1
        EM.add_timer(3) { send_getblocks }
        return get_genesis_block
      end
      pkt = Protocol.getblocks_pkt(@version.version, locator)
      log.info { "<< getblocks: #{locator.first}" }
      send_data(pkt)
    end

    # send +getheaders+ message
    def send_getheaders locator = @node.store.get_locator
      return get_genesis_block  if @node.store.get_depth == -1
      pkt = Protocol.pkt("getheaders", [Bitcoin::network[:magic_head],
          locator.size.chr, *locator.map{|l| l.htb_reverse}, "\x00"*32].join)
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
      if @version.version > Bitcoin::Protocol::BIP0031_VERSION
        @latency_ms = LATENCY_MAX
        @ping_nonce = rand(0xffffffff)
        @ping_time = Time.now
        log.debug { "<< ping (#{@ping_nonce})" }
        send_data(Protocol.ping_pkt(@ping_nonce))
      else
        # set latency to 5 seconds, terrible but this version should be obsolete now
        @latency_ms = (5*1000)
        log.debug { "<< ping" }
        send_data(Protocol.ping_pkt)
      end
    end

    # ask for the genesis block
    def get_genesis_block
      log.info { "Asking for genesis block" }
      pkt = Protocol.getdata_pkt(:block, [Bitcoin::network[:genesis_hash].htb])
      send_data(pkt)
    end

    # received +ping+ message with given +nonce+.
    # send +pong+ message back, if +nonce+ is set.
    # network versions <=60000 don't set the nonce and don't expect a pong.
    def on_ping nonce
      log.debug { ">> ping (#{nonce})" }
      send_data(Protocol.pong_pkt(nonce))  if nonce
    end

    # received +pong+ message with given +nonce+.
    def on_pong nonce
      if @ping_nonce == nonce
        @latency_ms = (Time.now - @ping_time) * 1000.0
      end
      log.debug { ">> pong (#{nonce}), latency: #{@latency_ms.to_i}ms" }
    end

    # begin handshake; send +version+ message
    def on_handshake_begin
      @state = :handshake
      from = "#{@node.external_ip}:#{@node.config[:listen][1]}"
      version = Bitcoin::Protocol::Version.new({
        :version    => 70001,
        :last_block => @node.store.get_depth,
        :from       => from,
        :to         => @host,
        :user_agent => "/bitcoin-ruby:#{Bitcoin::VERSION}/",
        #:user_agent => "/Satoshi:0.8.1/",
      })
      send_data(version.to_pkt)
      log.debug { "<< version (#{Bitcoin.network[:protocol_version]})" }
    end

    # get Addr object for this connection
    def addr
      return @addr  if @addr
      @addr = P::Addr.new
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
        :version => (@version.version rescue 0), :block => @version.last_block,
        :started => @started.to_i, :user_agent => @version.user_agent
      }
    end

    def incoming?; @direction == :in; end
    def outgoing?; @direction == :out; end

  end

end
