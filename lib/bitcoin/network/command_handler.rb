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
  end

  # wrap logger and append prefix
  def log
    @log ||= Bitcoin::Logger::LogWrapper.new("command:", @node.log)
  end

  # respond to a command; send serialized response to the client
  def respond(cmd, data)
    return  unless data
    @lock.synchronize do
      send_data([cmd, data].to_json + "\x00")
    end
  end

  # receive request from the client
  def receive_data data
    @buf.extract(data).each do |packet|
      begin
        cmd, args = JSON::parse(packet)
        log.debug { [cmd, args] }
        if cmd == "relay_tx"
          handle_relay_tx(*args)
          return
        end
        if respond_to?("handle_#{cmd}")
          respond(cmd, send("handle_#{cmd}", *args))
        else
          respond(cmd, { error: "unknown command: #{cmd}. send 'help' for help." })
        end
      rescue ArgumentError
        respond(cmd, { error: $!.message })
      end
    end
  rescue Exception
    p $!; puts *$@
  end

  # handle +monitor+ command; subscribe client to specified channels
  # (+block+, +tx+, +output+, +connection+).
  # Some commands can have parameters, e.g. the number of confirmations
  # +tx+ or +output+ should have. Parameters are appended to the command
  # name after an underscore (_), e.g. subscribe to channel "tx_6" to
  # receive only transactions with 6 confirmations.
  # 
  # Receive new blocks:
  #  bitcoin_node monitor block
  # Receive new (unconfirmed) transactions:
  #  bitcoin_node monitor tx
  # Receive transactions with 6 confirmations:
  #  bitcoin_node monitor tx_6 
  # Receive [txhash, address, value] for each output:
  #  bitcoin_node monitor output
  # Receive peer connections/disconnections:
  #  bitcoin_node monitor connection"
  # Combine multiple channels:
  #  bitcoin_node monitor "block tx tx_1 tx_6 connection"
  # 
  # NOTE: When a new block is found, it might include transactions that we
  # didn't previously receive as unconfirmed. To make sure you receive all
  # transactions, also subscribe to the tx_1 channel.
  def handle_monitor *channels
    channels.map(&:to_sym).each do |channel|
      @node.subscribe(channel) {|*data| respond("monitor", [channel, *data]) }
      name, *params = channel.to_s.split("_")
      send("handle_monitor_#{name}", *params)
      log.info { "Client subscribed to channel #{channel}" }
    end
    nil
  end

  # Handle +monitor block+ command; send the current chain head
  # after client is subscribed to :block channel
  def handle_monitor_block
    head = Bitcoin::P::Block.new(@node.store.get_head.to_payload) rescue nil
    respond("monitor", ["block", [head, @node.store.get_depth]])  if head
  end

  # Handle +monitor tx+ command.
  # When +conf+ is given, don't subscribe to the :tx channel for unconfirmed
  # transactions. Instead, subscribe to the :block channel, and whenever a new
  # block comes in, send all transactions that now have +conf+ confirmations.
  def handle_monitor_tx conf = nil
    return  unless conf
    if conf.to_i == 0 # 'tx_0' is just an alias for 'tx'
      return @node.subscribe(:tx) {|*a| @node.notifiers[:tx_0].push(*a) }
    end
    @node.subscribe(:block) do |block, depth|
      block = @node.store.get_block_by_depth(depth - conf.to_i + 1)
      next  unless block
      block.tx.each {|tx| @node.notifiers["tx_#{conf}".to_sym].push([tx, conf.to_i]) }
    end
  end

  # Handle +monitor output+ command.
  # Receive tx hash, recipient address and value for each output.
  # This allows easy scanning for new payments without parsing the
  # tx format and running scripts.
  # See #handle_monitor_tx for confirmation behavior.
  def handle_monitor_output conf = 0
    return  unless (conf = conf.to_i) > 0
    @node.subscribe(:block) do |block, depth|
      block = @node.store.get_block_by_depth(depth - conf + 1)
      next  unless block
      block.tx.each do |tx|
        tx.out.each do |out|
          addr = Bitcoin::Script.new(out.pk_script).get_address
          res = [tx.hash, addr, out.value, conf]
          @node.push_notification("output_#{conf}".to_sym, res)
        end
      end
    end
  end

  # Handle +monitor connection+ command; send current connections
  # after client is subscribed to :connection channel.
  def handle_monitor_connection
    @node.connections.select {|c| c.connected?}.each do |conn|
      respond("monitor", [:connection, [:connected, conn.info]])
    end
  end

  # Get various statistics.
  #  bitcoin_node info
  def handle_info
    blocks = @node.connections.map(&:version).compact.map(&:last_block) rescue nil
    established = @node.connections.select {|c| c.state == :connected }
    info = {
      :blocks => "#{@node.store.get_depth} (#{(blocks.inject{|a,b| a+=b; a } / blocks.size rescue '?' )})#{@node.store.in_sync? ? ' sync' : ''}",
      :addrs => "#{@node.addrs.select{|a| a.alive?}.size} (#{@node.addrs.size})",
      :connections => "#{established.size} established (#{established.select(&:outgoing?).size} out, #{established.select(&:incoming?).size} in), #{@node.connections.size - established.size} connecting",
      :queue => @node.queue.size,
      :inv_queue => @node.inv_queue.size,
      :inv_cache => @node.inv_cache.size,
      :network => @node.config[:network],
      :storage => @node.config[:storage],
      :version => Bitcoin.network[:protocol_version],
      :external_ip => @node.external_ip,
      :uptime => format_uptime(@node.uptime),
    }
    Bitcoin.namecoin? ? {:names => @node.store.db[:names].count}.merge(info) : info
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
      "#{c.host.rjust(15)}:#{c.port} [#{c.direction}, state: #{c.state}, " +
      "version: #{c.version.version rescue '?'}, " +
      "block: #{c.version.block rescue '?'}, " +
      "uptime: #{format_uptime(c.uptime) rescue 0}, " +
      "client: #{c.version.user_agent rescue '?'}]" }
  end

  # Connect to given peer(s).
  #  bitcoin_node connect <ip>:<port>[,<ip>:<port>]
  def handle_connect *args
    args.each {|a| @node.connect_peer(*a.split(':')) }
    {:state => "Connecting..."}
  end

  # Disconnect given peer(s).
  #  bitcoin_node disconnect <ip>:<port>[,<ip>,<port>]
  def handle_disconnect *args
    args.each do |c|
      host, port = *c.split(":")
      conn = @node.connections.select{|c| c.host == host && c.port == port.to_i}.first
      conn.close_connection  if conn
    end
    {:state => "Disconnected"}
  end

  # Trigger the node to ask its peers for new blocks.
  #  bitcoin_node getblocks
  def handle_getblocks
    @node.connections.sample.send_getblocks
    {:state => "Sending getblocks..."}
  end

  # Trigger the node to ask its for new peer addresses.
  #  bitcoin_node getaddr
  def handle_getaddr
    @node.connections.sample.send_getaddr
    {:state => "Sending getaddr..."}
  end

  # Get known peer addresses (used by bin/bitcoin_dns_seed).
  #  bitcoin_node addrs [count]
  def handle_addrs count = 32
    @node.addrs.weighted_sample(count.to_i) do |addr|
      Time.now.tv_sec + 7200 - addr.time
    end.map do |addr|
      [addr.ip, addr.port, Time.now.tv_sec - addr.time] rescue nil
    end.compact
  end

  # Trigger a rescan operation when used with a UtxoStore.
  #  bitcoin_node rescan
  def handle_rescan
    EM.defer { @node.store.rescan }
    {:state => "Rescanning ..."}
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
  def handle_create_tx keys, recipients, fee = 0
    keystore = Bitcoin::Wallet::SimpleKeyStore.new(file: StringIO.new("[]"))
    keys.each do |k|
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
    tx = wallet.new_tx(recipients.map {|r| [:address, r[0], r[1]]}, fee)
    return { error: "Error creating tx." }  unless tx
    [ tx.to_payload.hth, tx.in.map {|i| [i.sig_hash.hth, i.sig_address] rescue nil } ]
  rescue
    { error: "Error creating tx: #{$!.message}" }
  end

  # Assemble an unsigned transaction from the +tx_hex+ and +sig_pubkeys+.
  # The +tx_hex+ is the regular transaction structure, with empty input scripts
  # (as returned by #create_tx when called without privkeys).
  # +sig_pubkeys+ is an array of [signature, pubkey] pairs used to build the
  # input scripts.
  def handle_assemble_tx tx_hex, sig_pubs
    tx = Bitcoin::P::Tx.new(tx_hex.htb)
    sig_pubs.each.with_index do |sig_pub, idx|
      sig, pub = *sig_pub.map(&:htb)
      script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, pub)
      tx.in[idx].script_sig_length = script_sig.bytesize
      tx.in[idx].script_sig = script_sig
    end
    tx = Bitcoin::P::Tx.new(tx.to_payload)
    tx.validator(@node.store).validate(raise_errors: true)
    tx.to_payload.hth
  rescue
    { error: "Error assembling tx: #{$!.message}" }
  end

  # Relay given transaction (in hex).
  #  bitcoin_node relay_tx <tx in hex>
  def handle_relay_tx hex, send = 3, wait = 3
    begin
      tx = Bitcoin::P::Tx.new(hex.htb)
    rescue
      return respond("relay_tx", { error: "Error decoding transaction." })
    end

    validator = tx.validator(@node.store)
    unless validator.validate(rules: [:syntax])
      return respond("relay_tx", { error: "Transaction syntax invalid.",
                     details: validator.error })
    end
    unless validator.validate(rules: [:context])
      return respond("relay_tx", { error: "Transaction context invalid.",
                     details: validator.error })
    end

    #@node.store.store_tx(tx)
    @node.relay_tx[tx.hash] = tx
    @node.relay_propagation[tx.hash] = 0
    @node.connections.select(&:connected?).sample(send).each {|c| c.send_inv(:tx, tx.hash) }

    EM.add_timer(wait) do
      received = @node.relay_propagation[tx.hash]
      total = @node.connections.select(&:connected?).size - send
      percent = 100.0 / total * received
      respond("relay_tx", { success: true, hash: tx.hash, propagation: {
                  received: received, sent: 1, percent: percent } })
    end
  rescue
    respond("relay_tx", { error: $!.message, backtrace: $@ })
  end

  # Stop the bitcoin node.
  #  bitcoin_node stop
  def handle_stop
    Thread.start { sleep 0.1; @node.stop }
    {:state => "Stopping..."}
  end

  # List all available commands.
  #  bitcoin_node help
  def handle_help
    self.methods.grep(/^handle_(.*?)/).map {|m| m.to_s.sub(/^(.*?)_/, '')}
  end

  # Validate and store given block (in hex) as if it was received by a peer.
  #  bitcoin_node store_block <block in hex>
  def handle_store_block hex
    block = Bitcoin::P::Block.new(hex.htb)
    @node.queue << [:block, block]
    { queued: [ :block, block.hash ] }
  end

  # Store given transaction (in hex) as if it was received by a peer.
  #  bitcoin_node store_tx <tx in hex>
  def handle_store_tx hex
    tx = Bitcoin::P::Tx.new(hex.htb)
    @node.queue << [:tx, tx]
    { queued: [ :tx, tx.hash ] }
  end

  # format node uptime
  def format_uptime t
    mm, ss = t.divmod(60)            #=> [4515, 21]
    hh, mm = mm.divmod(60)           #=> [75, 15]
    dd, hh = hh.divmod(24)           #=> [3, 3]
    "%02d:%02d:%02d:%02d" % [dd, hh, mm, ss]
  end

  # disconnect notification clients when connection is closed
  def unbind
    #@node.notifiers.unsubscribe(@notify_sid)  if @notify_sid
    @node.command_connections.delete(self)
  end

end
