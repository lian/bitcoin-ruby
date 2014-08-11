# encoding: ascii-8bit

require 'json'
require 'monitor'

# Started by the Node, accepts connections from CommandClient and answers requests or
# registers for events and notifies the clients when they happen.
class Bitcoin::Network::CommandHandler < EM::Connection

  # create new CommandHandler
  def initialize node
    @node = node
    @node.command_connections << self
    @buf = BufferedTokenizer.new("\x00")
    @lock = Monitor.new
    @monitors = []
  end

  # wrap logger and append prefix
  def log
    @log ||= Bitcoin::Logger::LogWrapper.new("command:", @node.log)
  end

  # respond to a command; send serialized response to the client
  def respond(request, data)
    return  unless data
    request[:result] = data
    request.delete(:params)
    @lock.synchronize do
      send_data(request.to_json + "\x00")
    end
  end

  # receive request from the client
  def receive_data data
    @buf.extract(data).each do |packet|
      begin
        request = symbolize_keys(JSON::parse(packet))
        log.debug { request }
        case request[:method]
        when "relay_tx"
          return handle_relay_tx(request, request[:params])
        when "monitor"
          respond(request, handle_monitor(request, request[:params]))
        else
          if respond_to?("handle_#{request[:method]}")
            if request[:params] && request[:params].any?
              respond(request, send("handle_#{request[:method]}", request[:params]))
            else
              respond(request, send("handle_#{request[:method]}"))
            end
          else
            respond(request, { error: "unknown command: #{request[:method]}. send 'help' for help." })
          end
        end
      rescue
        respond(request, { error: $!.message })
        p $!; puts *$@
      end
    end
  rescue
    p $!; puts *$@
  end

  def handle_connected
    "connected"
  end

  # Handle +monitor+ command; subscribe client to specified channels
  # (+block+, +tx+, +output+, +connection+).
  # Parameters can be appended to the channel name, e.g. the number of confirmations
  # +tx+ or +output+ should have. Parameters are appended to the command
  # name after an underscore (_), e.g. subscribe to channel "tx_6" to
  # receive only transactions with 6 confirmations.
  # You can send the last block/tx/output you know about, and it will also send you
  # all the objects you're missing.
  #
  # Receive new blocks:
  #  bitcoin_node monitor block
  # Receive blocks since block 123, and new ones as they come in:
  #  bitcoin_node monitor block_123
  # Receive new (unconfirmed) transactions:
  #  bitcoin_node monitor tx
  # Receive transactions with 6 confirmations:
  #  bitcoin_node monitor tx_6
  # Receive transactions since <txhash>, and new ones as they come in:
  #  bitcoin_node monitor tx_1_<txhash>
  # Receive [txhash, idx, address, value] for each output:
  #  bitcoin_node monitor output
  # Receive outputs since <txhash>:<idx>, and new ones as they come in:
  #  bitcoin_node monitor output_1_<txhash>:<idx>
  # Receive peer connections/disconnections:
  #  bitcoin_node monitor connection"
  # Combine multiple channels:
  #  bitcoin_node monitor "block tx tx_1 tx_6 connection"
  #
  # NOTE: When a new block is found, it might include transactions that we
  # didn't previously receive as unconfirmed. To make sure you receive all
  # transactions, also subscribe to the tx_1 channel.
  def handle_monitor request, params
    log.info { "Client subscribed to channel #{params[:channel].inspect}" }
    { id: send("handle_monitor_#{params[:channel]}", request, params) }
  end

  # Handle +unmonitor+ command; cancel given subscription.
  # Parameter +id+ must be the subscription ID that was returned when calling +monitor+.
  def handle_unmonitor request
    id = request[:id]
    raise "Monitor #{id} not found."  unless @monitors[id]
    @monitors[id][:channels].each {|name, id| @node.unsubscribe(name, id) }
    { id: id }
  end

  # Handle +monitor block+ command;
  def handle_monitor_block request, params
    monitor_id = @monitors.size
    id = @node.subscribe(:block) {|blk, depth| respond_monitor_block(request, blk, depth) }
    add_monitor(params, [[:block, id]])
    respond_missed_blocks(request, monitor_id)  if params[:last]
    monitor_id
  end

  def respond_missed_blocks request, monitor_id
    params = @monitors[monitor_id][:params]
    blk = @node.store.get_block(params[:last])
    respond_monitor_block(request, blk)
    while blk = blk.get_next_block
      respond_monitor_block(request, blk)
    end
  end

  def respond_monitor_block request, block, depth = nil
    depth ||= block.depth
    respond(request, { hash: block.hash, hex: block.to_payload.hth, depth: depth })
  end

  # TODO: params (min reorg depth)
  def handle_monitor_reorg request, params
    id = @node.subscribe(:reorg) do |new_main, new_side|
      respond(request, { new_main: new_main, new_side: new_side })
    end

    add_monitor(params, [[:reorg, id]])
  end

  # Handle +monitor tx+ command.
  # When +conf+ is given, don't subscribe to the :tx channel for unconfirmed
  # transactions. Instead, subscribe to the :block channel, and whenever a new
  # block comes in, send all transactions that now have +conf+ confirmations.
  def handle_monitor_tx request, params
    monitor_id = @monitors.size
    tx_id = @node.subscribe(:tx) {|tx, conf| respond_monitor_tx(request, monitor_id, tx, conf) }

    conf = params[:conf].to_i
    block_id = @node.subscribe(:block) do |block, depth|
      next  unless block = @node.store.get_block_by_depth(depth - conf + 1)
      block.tx.each {|tx| respond_monitor_tx(request, monitor_id, tx, conf) }
    end

    add_monitor(params, [[:tx, tx_id], [:block, block_id]])

    respond_missed_txs(request, params, monitor_id)  if params[:last]

    monitor_id
  end

  def respond_missed_txs request, params, monitor_id
    return  unless last_tx = @node.store.get_tx(params[:last])
    notify = false; depth = @node.store.get_depth
    (last_tx.get_block.depth..depth).each do |i|
      blk = @node.store.get_block_by_depth(i)
      blk.tx.each do |tx|
        respond_monitor_tx(request, monitor_id, tx, (depth - blk.depth + 1))  if notify
        notify = true  if tx.hash == last_tx.hash
      end
    end
  end

  def respond_monitor_tx request, monitor_id, tx, conf = nil
    conf ||= tx.confirmations

    params = @monitors[monitor_id][:params]

    # filter by addresses
    if params[:addresses]
      addrs = tx.out.map(&:parsed_script).map(&:get_address)
      return  unless (params[:addresses] & addrs).any?
    end

    respond(request, { hash: tx.hash, nhash: tx.nhash, hex: tx.to_payload.hth, conf: conf })
  end

  # Handle +monitor output+ command.
  # Receive tx hash, recipient address and value for each output.
  # This allows easy scanning for new payments without parsing the
  # tx format and running scripts.
  # See #handle_monitor_tx for confirmation behavior.
  def handle_monitor_output request, params
    monitor_id = @monitors.size

    tx_id = @node.subscribe(:tx) do |tx, conf|
      tx.out.each.with_index do |out, idx|
        respond_monitor_output(request, monitor_id, tx, out, idx, conf)
      end
    end

    if (conf = params[:conf].to_i) > 0
      block_id = @node.subscribe(:block) do |block, depth|
        block = @node.store.get_block_by_depth(depth - conf + 1)
        next  unless block
        block.tx.each do |tx|
          tx.out.each.with_index do |out, idx|
            respond_monitor_output(request, monitor_id, tx, out, idx, conf)
          end
        end
      end
    end

    add_monitor(params, [[:tx, tx_id], [:block, block_id]])

    respond_missed_outputs(request, monitor_id)  if params[:last]

    monitor_id
  end

  def respond_missed_outputs request, monitor_id
    params = @monitors[monitor_id][:params]
    last_hash, last_idx = *params[:last].split(":"); last_idx = last_idx.to_i
    return  unless last_tx = @node.store.get_tx(last_hash)
    return  unless last_out = last_tx.out[last_idx]
    notify = false
    depth = @node.store.get_depth
    (last_tx.get_block.depth..depth).each do |i|
      blk = @node.store.get_block_by_depth(i)
      blk.tx.each do |tx|
        tx.out.each.with_index do |out, idx|
          if notify
            respond_monitor_output(request, monitor_id, tx, out, idx, (depth - blk.depth + 1))
          else
            notify = true  if tx.hash == last_hash && idx == last_idx
          end
        end
      end
    end
  end

  def respond_monitor_output request, monitor_id, tx, out, idx, conf
    addr = out.parsed_script.get_address

    params = @monitors[monitor_id][:params]

    # filter by addresses
    return  if params[:addresses] && !params[:addresses].include?(addr)

    respond(request, { nhash: tx.nhash, hash: tx.hash, idx: idx,
        address: addr, value: out.value, conf: conf })
  end

  # Handle +filter monitor output+ command; add given +address+ to the list of
  # filtered addresses in the params of the given monitor.
  def handle_filter_monitor_output request
    @monitors[request[:id]][:params][:addresses] << request[:address]
    { id: request[:id] }
  end

  # Handle +monitor connection+ command; send current connections
  # after client is subscribed to :connection channel.
  def handle_monitor_connection request, params
    id = @node.subscribe(:connection) {|data| respond(request, data) }
      @node.connections.select {|c| c.connected?}.each do |conn|
      respond(request, conn.info.merge(type: :connected))
    end
    add_monitor(params, [[:connection, id]])
  end

  # Get various statistics.
  #  bitcoin_node info
  def handle_info
    blocks = @node.connections.map(&:version).compact.map(&:last_block) rescue nil
    established = @node.connections.select {|c| c.state == :connected }
    info = {
      blocks: {
        depth: @node.store.get_depth,
        peers: (blocks.inject{|a,b| a+=b; a } / blocks.size rescue '?' ),
        sync: @node.store.in_sync?,
      },
      addrs: {
        alive: @node.addrs.select{|a| a.alive?}.size,
        total: @node.addrs.size,
      },
      connections: {
        established: established.size,
        outgoing: established.select(&:outgoing?).size,
        incoming: established.select(&:incoming?).size,
        connecting: @node.connections.size - established.size,
      },
      queue: @node.queue.size,
      inv_queue: @node.inv_queue.size,
      inv_cache: @node.inv_cache.size,
      network: @node.config[:network],
      storage: @node.config[:storage],
      version: Bitcoin.network[:protocol_version],
      external_ip: @node.external_ip,
      uptime: @node.uptime,
    }
    Bitcoin.namecoin? ? {names: @node.store.db[:names].count}.merge(info) : info
  end

  def add_monitor params, channels
    @monitors << { params: params, channels: channels }
    @monitors.size - 1
  end


  # Get the currently active configuration.
  #  bitcoin_node config
  def handle_config
    @node.config
  end

  # Get currently connected peers.
  #  bitcoin_node connections
  def handle_connections
    @node.connections.sort{|x,y| y.uptime <=> x.uptime}.map{|c|
      {
        type: c.direction, host: c.host, port: c.port, state: c.state,
        uptime: c.uptime,
        version: {
          version: c.version.version,
          services: c.version.services,
          time: c.version.time,
          nonce: c.version.nonce,
          block: c.version.last_block,
          client: (c.version.user_agent rescue '?'),
          relay: c.version.relay,
        }
      }
    }
  end

  # Connect to given peer(s).
  #  { method: "connect", params: {host: "localhost", port: 12345 }
  def handle_connect params
    @node.connect_peer(params[:host], params[:port])
    { state: :connecting }
  end

  # Disconnect given peer(s).
  #  { method: "disconnect", params: {host: "localhost", port: 12345 }
  def handle_disconnect params
    conn = @node.connections.find {|c| c.host == params[:host] && c.port == params[:port].to_i}
    conn.close_connection  if conn
    { state: :disconnected }
  end

  # Trigger the node to ask its peers for new blocks.
  #  { method: "getblocks", params: {} }
  def handle_getblocks
    conn = @node.connections.sample
    if conn
      conn.send_getblocks
      { state: :sent, peer: { host: conn.host, port: conn.port } }
    else
      raise "No peer connected"
    end
  end

  # Trigger the node to ask its for new peer addresses.
  #  { method: "getaddr", params: {} }
  def handle_getaddr
    conn = @node.connections.sample
    if conn
      conn.send_getaddr
      { state: :sent, peer: { host: conn.host, port: conn.port } }
    else
      raise "No peer connected"
    end
  end

  # Get known peer addresses (used by bin/bitcoin_dns_seed).
  #  { method: "getaddr", params: { count: 32 } }
  def handle_addrs params = { count: 32 }
    @node.addrs.weighted_sample(params[:count].to_i) do |addr|
      Time.now.tv_sec + 7200 - addr.time
    end.map do |addr|
      [addr.ip, addr.port, Time.now.tv_sec - addr.time] rescue nil
    end.compact
  end

  # Trigger a rescan operation when used with a UtxoStore.
  #  { method: "rescan" }
  def handle_rescan
    EM.defer {
      begin
        @node.store.rescan
      rescue
        puts "rescan: #{$!}"
      end
      }
    { state: :rescanning }
  end

  # Get Time Since Last Block.
  #  bitcoin_node tslb
  def handle_tslb
    { tslb: (Time.now - @node.last_block_time).to_i }
  end

  # Create a transaction, collecting outputs from given +keys+, spending to +recipients+
  # with an optional +fee+.
  # Keys is an array that can contain either privkeys, pubkeys or addresses.
  # When a privkey is given, the corresponding inputs are signed. If not, the
  # signature_hash is computed and passed along with the response.
  # After creating an unsigned transaction, one just needs to sign the sig_hashes
  # and send everything to #assemble_tx, to receive the complete transaction that
  # can be relayed to the network.
  def handle_create_tx params = {}
    params[:fee] ||= 0
    #keys, recipients, fee = 0
    keystore = Bitcoin::Wallet::SimpleKeyStore.new(file: StringIO.new("[]"))
    params[:keys].each do |k|
      begin
        key = Bitcoin::Key.from_base58(k)
        key = { addr: key.addr, key: key }
      rescue
        if Bitcoin.valid_address?(k)
          key = { addr: k }
        else
          begin
            key = Bitcoin::Key.new(nil, k)
            key = { addr: key.addr, key: key }
          rescue
            return { error: "Input not valid address, pub- or privkey: #{k}" }
          end
        end
      end
      keystore.add_key(key)
    end
    wallet = Bitcoin::Wallet::Wallet.new(@node.store, keystore)

    tx = wallet.new_tx(params[:recipients].map {|r| [:address, r[0], r[1]]}, params[:fee])
    return { error: "Error creating tx." }  unless tx
    { hash: tx.hash, hex: tx.to_payload.hth,
      missing_sigs: tx.in.map {|i| [i.sig_hash.hth, i.sig_address] rescue nil } }
  rescue
    { error: "Error creating tx: #{$!.message}" }
    p $!; puts *$@
  end

  # Assemble an unsigned transaction from the +tx+ and +sig_pubkeys+ params.
  # The +tx+ is the regular transaction structure, with empty input scripts
  # (as returned by #create_tx when called without privkeys).
  # +sig_pubkeys+ is an array of [signature, pubkey] pairs used to build the
  # input scripts.
  def handle_assemble_tx params = {}
    # tx_hex, sig_pubs
    tx = Bitcoin::P::Tx.new(params[:tx].htb)
    params[:sig_pubs].each.with_index do |sig_pub, idx|
      sig, pub = *sig_pub.map(&:htb)
      script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, pub)
      tx.in[idx].script_sig_length = script_sig.bytesize
      tx.in[idx].script_sig = script_sig
    end
    tx = Bitcoin::P::Tx.new(tx.to_payload)
    tx.validator(@node.store).validate(raise_errors: true)
    { hash: tx.hash, hex: tx.to_payload.hth }
  rescue
    { error: "Error assembling tx: #{$!.message}" }
    p $!; puts *$@
  end

  # Relay given transaction (in hex).
  #  bitcoin_node relay_tx <tx in hex>
  def handle_relay_tx request, params = {}
    params[:send] ||= 3
    params[:wait] ||= 3
    # request, hex, send = 3, wait = 3
    begin
      tx = Bitcoin::P::Tx.new(params[:hex].htb)
    rescue
      return respond(request, { error: "Error decoding transaction." })
    end

    validator = tx.validator(@node.store)
    unless validator.validate(rules: [:syntax])
      return respond(request, { error: "Transaction syntax invalid.",
                     details: validator.error })
    end
    unless validator.validate(rules: [:context])
      return respond(request, { error: "Transaction context invalid.",
                     details: validator.error })
    end

    #@node.store.store_tx(tx)
    @node.relay_tx[tx.hash] = tx
    @node.relay_propagation[tx.hash] = 0
    @node.connections.select(&:connected?).sample(params[:send]).each {|c| c.send_inv(:tx, tx.hash) }

    EM.add_timer(params[:wait]) do
      received = @node.relay_propagation[tx.hash]
      total = @node.connections.select(&:connected?).size - params[:send]
      percent = 100.0 / total * received
      respond(request, { success: true, hash: tx.hash, propagation: {
            received: received, sent: 1, percent: percent } })
    end
  rescue
    respond(request, { error: $!.message, backtrace: $@ })
    p $!; puts *$@
  end

  # Stop the bitcoin node.
  #  bitcoin_node stop
  def handle_stop
    Thread.start { sleep 0.1; @node.stop }
    { state: :stopping }
  end

  # List all available commands.
  #  bitcoin_node help
  def handle_help
    self.methods.grep(/^handle_(.*?)/).map {|m| m.to_s.sub(/^(.*?)_/, '')}
  end

  # Validate and store given block (in hex) as if it was received by a peer.
  #  { method: "store_block", params: { hex: <block data in hex> } }
  def handle_store_block params
    block = Bitcoin::P::Block.new(params[:hex].htb)
    @node.queue << [:block, block]
    { queued: block.hash }
  end

  # Store given transaction (in hex) as if it was received by a peer.
  #  { method: "store_tx", params: { hex: <tx data in hex> } }
  def handle_store_tx params
    tx = Bitcoin::P::Tx.new(params[:hex].htb)
    @node.queue << [:tx, tx]
    { queued: tx.hash }
  end

  # # format node uptime
  # def format_uptime t
  #   mm, ss = t.divmod(60)            #=> [4515, 21]
  #   hh, mm = mm.divmod(60)           #=> [75, 15]
  #   dd, hh = hh.divmod(24)           #=> [3, 3]
  #   "%02d:%02d:%02d:%02d" % [dd, hh, mm, ss]
  # end

  # disconnect notification clients when connection is closed
  def unbind
    #@node.notifiers.unsubscribe(@notify_sid)  if @notify_sid
    @node.command_connections.delete(self)
  end

  private

  def symbolize_keys(obj)
    return obj  unless [Hash, Array].include?(obj.class)
    return obj.map {|v| symbolize_keys(v) }  if obj.is_a?(Array)
    obj.inject({}){|result, (key, value)|
      new_key = key.is_a?(String) ? key.to_sym : key
      new_value = case value
                  when Hash then symbolize_keys(value)
                  when Array then value.map {|v| symbolize_keys(v) }
                  else value; end
      result[new_key] = new_value
      result
    }
  end

end
