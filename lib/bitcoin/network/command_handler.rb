require 'json'

class CommandHandler < EM::Connection

  def initialize node
    @node = node
  end

  def post_init
  end

  def respond(data)
    send_data(data.to_json + "\n")
  end

  def receive_data line
    return  if line == "\n"
    cmd, *args = line.split(" ")
    @node.log.debug { "debug cmd: #{line}" }
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
    }
  end

  def handle_config
    @node.config
  end

  def handle_connections
    @node.connections.sort{|x,y| x.host <=> y.host}.map{|c|
      "#{c.host.rjust(15)}:#{c.port} - #{c.state} - " +
      "#{c.version.version rescue '?'} - #{c.version.block rescue '?'}"}
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
