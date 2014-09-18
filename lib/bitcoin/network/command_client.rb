# encoding: ascii-8bit

require 'json'

# Client to connect to CommandHandler and issue requests or register for events
class Bitcoin::Network::CommandClient < EM::Connection

  # create new client connecting to +host+:+port+ and executing callbacks from +block+,
  # passing +args+ in.
  #  CommandClient.connect(host, port) do
  #    on_connected { request("info") }
  #    on_info {|i| p i}
  #  end
  def initialize host, port, block, *args
    @host, @port = host, port
    @args = args
    @callbacks = {}
    @block = block
    instance_eval &block  if block
    @buffer = BufferedTokenizer.new("\x00")
    @connection_attempts = 0
    @requests = {}
    @i = 0
  end

  def log;
    @log ||= Bitcoin::Logger.create(:client)
  end

  def self.connect host, port, *args, &block
    client = EM.connect(host, port.to_i, self, host, port.to_i, block, *args)
  end

  # call +connected+ callback
  def post_init
    log.debug { "Connected" }
    request(:connected) { callback(:connected) }
  end

  # call +disconnected+ callback and try to reconnect
  def unbind
    log.debug { "Disconnected." }
    callback :disconnected
    EM.add_timer(@connection_attempts) do
      @connection_attempts += 1
      reconnect(@host, @port)
      post_init
    end
  end

  # request command +cmd+ with +args+ from the server
  def request cmd, params = nil, &block
    id = @i += 1
    @requests[id] = block  if block
    log.debug { "request: #{cmd} #{args.inspect}" }
    register_monitor_callbacks(params)  if cmd.to_sym == :monitor
    request = { id: id, method: cmd }
    request[:params] = params  if params
    send_data(request.to_json + "\x00")
  end

  # receive response from server
  def receive_data data
    @connection_attempts = 0
    @buffer.extract(data).each do |packet|
      response = JSON.parse(packet)
      log.debug { d = response['result'].inspect
        "response: #{response['method']} #{d[0...50]}#{d.size > 50 ? '...' : ''}" }
      if cb = @requests[response['id']]
        cb.call(response['result'])
      else
        callback(:response, response['method'], response['result'])
        callback(response['method'].to_sym, response['result'])
      end
    end
  end

  # call the callback specified by +name+ passing in +args+
  def callback name, *args
    cb = @callbacks[name.to_sym]
    return  unless cb
    log.debug { "callback: #{name}" }
    cb.call(*args)
  end

  # register callback methods
  def method_missing(name, *args, &block)
    if name =~ /^on_/
      @callbacks[name.to_s.split("on_")[1].to_sym] = block
      log.debug { "callback #{name} registered" }
    else
      super(name, *args)
    end
  end

  # register callbacks for monitor
  def register_monitor_callbacks params
    on_monitor do |data|
      next  if data.is_a?(Hash) && data.keys == ["id"]
      callback(params["channel"], data)
    end
  end

end
