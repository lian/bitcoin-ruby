class Bitcoin::Network::CommandClient < EM::Connection

  def initialize host, port, block, *args
    @host, @port = host, port
    @args = args
    @callbacks = {}
    @block = block
    instance_eval &block  if block
    @buffer = BufferedTokenizer.new("\x00")
  end

  def log
    return @log  if @log
    @log = Bitcoin::Logger.create("command_client")
    @log.level = :info
    @log
  end

  def self.connect host, port, *args, &block
    client = EM.connect(host, port.to_i, self, host, port.to_i, block, *args)
  end

  def post_init
    log.info { "Connected" }
    callback :connected
  end

  def unbind
    log.info { "Disconnected" }
    callback :disconnected
    EM.add_timer(1) do
      reconnect(@host, @port)
      post_init
    end
  end

  def request cmd, *args
    log.info { "request: #{cmd} #{args.inspect}" }
    register_monitor_callbacks  if cmd.to_sym == :monitor
    send_data([cmd, args].to_json + "\x00")
  end

  def receive_data data
    @buffer.extract(data).each do |packet|
      cmd, *data = *JSON.load(packet)
      log.info { d = data.inspect
        "response: #{cmd} #{d[0...50]}#{d.size > 50 ? '...' : ''}" }
      callback(:response, cmd, *data)
      callback(cmd.to_sym, *data)
    end
  end

  def callback name, *args
    cb = @callbacks[name.to_sym]
    return  unless cb
    log.debug { "callback: #{name}" }
    cb.call(*args)
  end

  def method_missing(name, *args, &block)
    if name =~ /^on_/
      @callbacks[name.to_s.split("on_")[1].to_sym] = block
      log.debug { "callback #{name} registered" }
    else
      super(name, *args)
    end
  end

  def register_monitor_callbacks
    on_monitor do |type, data|
      callback(type, *data)
    end
  end

end
