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
      cmd, args = JSON::parse(packet)
      log.debug { [cmd, args] }
      if cmd == "relay_tx"
        handle_relay_tx(*args)
        return
      end
      if respond_to?("handle_#{cmd}")
        respond(cmd, send("handle_#{cmd}", *args))
      else
        respond(cmd, {:error => "unknown command: #{cmd}. send 'help' for help."})
      end
    end
  rescue Exception
    p $!
  end

  # handle +monitor+ command; subscribe client to specified channels
  # (+block+, +tx+, +connection+)
  #  bitcoin_node monitor block
  #  bitcoin_node monitor "block tx connection"
  def handle_monitor *channels
    channels.each do |channel|
      @node.notifiers[channel.to_sym].subscribe do |*data|
        respond("monitor", [channel, *data])
      end
      case channel.to_sym
      when :block
        head = Bitcoin::P::Block.new(@node.store.get_head.to_payload) rescue nil
        respond("monitor", ["block", [head, @node.store.get_depth.to_s]])  if head
      when :connection
        @node.connections.select {|c| c.connected?}.each do |conn|
          respond("monitor", [:connection, [:connected, conn.info]])
        end
      end
    end
    nil
  end

  # display various statistics
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

  # display configuration hash currently used
  #  bitcoin_node config
  def handle_config
    @node.config
  end

  # display connected peers
  #  bitcoin_node connections
  def handle_connections
    @node.connections.sort{|x,y| y.uptime <=> x.uptime}.map{|c|
      "#{c.host.rjust(15)}:#{c.port} [#{c.direction}, state: #{c.state}, " +
      "version: #{c.version.version rescue '?'}, " +
      "block: #{c.version.block rescue '?'}, " +
      "uptime: #{format_uptime(c.uptime) rescue 0}, " +
      "client: #{c.version.user_agent rescue '?'}]" }
  end

  # connect to given peer(s)
  #  bitcoin_node connect <ip>:<port>[,<ip>:<port>]
  def handle_connect *args
    args.each {|a| @node.connect_peer(*a.split(':')) }
    {:state => "Connecting..."}
  end

  # disconnect peer(s)
  #  bitcoin_node disconnect <ip>:<port>[,<ip>,<port>]
  def handle_disconnect *args
    args.each do |c|
      host, port = *c.split(":")
      conn = @node.connections.select{|c| c.host == host && c.port == port.to_i}.first
      conn.close_connection  if conn
    end
    {:state => "Disconnected"}
  end

  # trigger node to ask peers for new blocks
  #  bitcoin_node getblocks
  def handle_getblocks
    @node.connections.sample.send_getblocks
    {:state => "Sending getblocks..."}
  end

  # trigger node to ask for new peer addrs
  #  bitcoin_node getaddr
  def handle_getaddr
    @node.connections.sample.send_getaddr
    {:state => "Sending getaddr..."}
  end

  # display known peer addrs (used by bin/bitcoin_dns_seed)
  #  bitcoin_node addrs [count]
  def handle_addrs count = 32
    @node.addrs.weighted_sample(count.to_i) do |addr|
      Time.now.tv_sec + 7200 - addr.time
    end.map do |addr|
      [addr.ip, addr.port, Time.now.tv_sec - addr.time] rescue nil
    end.compact
  end

  def handle_tslb
    { tslb: (Time.now - @node.last_block_time).to_i }
  end

  # relay given transaction (in hex)
  #  bitcoin_node relay_tx <tx data>
  def handle_relay_tx data, send = 3, wait = 3
    begin
      tx = Bitcoin::Protocol::Tx.new(data.htb)
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

    @node.store.store_tx(tx)
    @node.relay_propagation[tx.hash] = 0
    @node.connections.select(&:connected?).sample(send).each {|c| c.send_inv(:tx, tx) }

    EM.add_timer(wait) do
      received = @node.relay_propagation[tx.hash]
      total = @node.connections.select(&:connected?).size - send
      percent = 100.0 / total * received
      respond("relay_tx", { success: true, hash: tx.hash, propagation: {
                  received: received, sent: 1, percent: percent } })
    end
  rescue
    respond("relay_tx", { error: $!.message })
  end

  # stop bitcoin node
  #  bitcoin_node stop
  def handle_stop
    Thread.start { sleep 0.1; @node.stop }
    {:state => "Stopping..."}
  end

  # list all commands
  #  bitcoin_node help
  def handle_help
    self.methods.grep(/^handle_(.*?)/).map {|m| m.to_s.sub(/^(.*?)_/, '')}
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
