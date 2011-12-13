require 'json'

class CommandHandler < EM::Connection

  def initialize node
    @node = node
  end

  def log
    @log ||= Bitcoin::Logger::LogWrapper.new("command:", @node.log)
  end

  def respond(data)
    send_data(data.to_json + "\n")
  end

  def receive_data line
    return  if line == "\n"
    cmd, *args = line.split(" ")
    log.debug { line.chomp }
    if respond_to?("handle_#{cmd}")
      respond(send("handle_#{cmd}", *args))
    else
      respond({:error => "unknown command: #{cmd}. send 'help' for help."})
    end
  end

  def handle_info
    blocks = @node.connections.map(&:version).compact.map(&:block) rescue nil
    {
      :blocks => "#{@node.store.get_depth} (#{(blocks.inject{|a,b| a+=b;a} / blocks.size rescue '?')})",
      :addrs => "#{@node.addrs.select{|a| a.alive?}.size} (#{@node.addrs.size})",
      :connections => "#{@node.connections.select{|c| c.state == :connected}.size} (#{@node.connections.size})",
      :queue => @node.queue.size,
      :inv_queue => @node.inv_queue.size,
      :network => @node.config[:network],
      :storage => @node.config[:storage],
      :version => Bitcoin::Protocol::VERSION,
      :uptime => Time.at(@node.uptime).utc.strftime("%H:%M:%S"),
    }
  end

  def handle_config
    @node.config
  end

  def handle_connections
    @node.connections.sort{|x,y| x.host <=> y.host}.map{|c|
      "#{c.host.rjust(15)}:#{c.port} [state: #{c.state}, " +
      "version: #{c.version.version rescue '?'}, " +
      "block: #{c.version.block rescue '?'}, " +
      "uptime: #{Time.at(c.uptime).utc.strftime("%H:%M:%S") rescue 0}]" }
  end

  def handle_connect *args
    args.each {|a| @node.connect_peer(*a.split(':')) }
    {:state => "Connecting..."}
  end

  def handle_getblocks
    @node.connections.sample.send_getblocks
    {:state => "Sending getblocks..."}
  end

  def handle_getaddr
    @node.connections.sample.send_getaddr
    {:state => "Sending getaddr..."}
  end

  def handle_stop
    Thread.start { sleep 0.1; @node.stop }
    {:state => "Stopping..."}
  end

  def handle_help
    self.methods.grep(/^handle_(.*?)/).map {|m| m.to_s.sub(/^(.*?)_/, '')}
  end

end
