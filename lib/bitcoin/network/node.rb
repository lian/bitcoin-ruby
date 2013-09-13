# encoding: ascii-8bit

Bitcoin.require_dependency :eventmachine
Bitcoin.require_dependency :json
require 'fileutils'

module Bitcoin::Network

  class Node

    # configuration hash
    attr_reader :config

    # logger
    attr_reader :log

    # connections to other peers (Array of ConnectionHandler)
    attr_reader :connections

    # command connections (Array of CommandHandler)
    attr_reader :command_connections

    # storage queue (blocks/tx waiting to be stored)
    attr_reader :queue

    # inventory queue (blocks/tx waiting to be downloaded)
    attr_reader :inv_queue

    # inventory cache (blocks/tx recently downloaded)
    attr_reader :inv_cache

    # Bitcoin::Storage backend
    attr_reader :store

    # peer addrs (Array of Bitcoin::Protocol::Addr)
    attr_reader :addrs

    # clients to be notified for new block/tx events
    attr_reader :notifiers

    # our external ip addresses we got told by peers
    attr_accessor :external_ips

    # time when the last main chain block was added
    attr_reader :last_block_time

    attr_accessor :relay_tx
    attr_accessor :relay_propagation


    DEFAULT_CONFIG = {
      :network => :bitcoin,
      :listen => ["0.0.0.0", Bitcoin.network[:default_port]],
      :connect => [],
      :command => ["127.0.0.1", 9999],
      :storage => "utxo::sqlite://~/.bitcoin-ruby/<network>/blocks.db",
      :mode => :full,
      :dns => true,
      :epoll_limit => 10000,
      :epoll_user => nil,
      :addr_file => "~/.bitcoin-ruby/<network>/peers.json",
      :log => {
        :network => :info,
        :storage => :info,
      },
      :max => {
        :connections_out => 8,
        :connections_in => 32,
        :connections => 8,
        :addr => 256,
        :queue => 501,
        :inv => 501,
        :inv_cache => 0,
        :unconfirmed => 100,
      },
      :intervals => {
        :queue => 1,
        :inv_queue => 1,
        :addrs => 5,
        :connect => 5,
        :relay => 0,
      },
      :import => nil,
      :skip_validation => false,
      :check_blocks => 1000,
    }

    def initialize config = {}
      @config = DEFAULT_CONFIG.deep_merge(config)
      @log = Bitcoin::Logger.create(:network, @config[:log][:network])
      @connections, @command_connections = [], []
      @queue, @queue_thread, @inv_queue, @inv_queue_thread = [], nil, [], nil
      set_store
      load_addrs
      @timers = {}
      @inv_cache = []
      @notifiers = {}
      @relay_propagation, @last_block_time, @external_ips = {}, Time.now, []
      @unconfirmed, @relay_tx = {}, {}
    end

    def set_store
      backend, config = @config[:storage].split('::')
      @store = Bitcoin::Storage.send(backend, {
          db: config, mode: @config[:mode], cache_head: true,
          skip_validation: @config[:skip_validation],
          log_level: @config[:log][:storage]}, ->(locator) {
          peer = @connections.select(&:connected?).sample
          peer.send_getblocks(locator)
        })
      @store.log.level = @config[:log][:storage]
      @store.check_consistency(@config[:check_blocks])
      if @config[:import]
        @importing = true
        EM.defer do
          begin
            @store.import(@config[:import]); @importing = false
          rescue
            log.fatal { $!.message }
            puts *$@
            stop
          end
        end
      end
    end

    def load_addrs
      file = @config[:addr_file].sub("~", ENV["HOME"])
        .sub("<network>", Bitcoin.network_name.to_s)
      unless File.exist?(file)
        @addrs = []
        FileUtils.mkdir_p(File.dirname(file))
        return
      end
      @addrs = JSON.load(File.read(file)).map do |a|
        addr = Bitcoin::P::Addr.new
        addr.time, addr.service, addr.ip, addr.port =
          a['time'], a['service'], a['ip'], a['port']
        addr
      end
      log.info { "Initialized #{@addrs.size} addrs from #{file}." }
    rescue
      @addrs = []
      log.warn { "Error loading addrs from #{file}." }
    end

    def store_addrs
      return  if !@addrs || !@addrs.any?
      file = @config[:addr_file].sub("~", ENV["HOME"])
        .sub("<network>", Bitcoin.network_name.to_s)
      FileUtils.mkdir_p(File.dirname(file))
      File.open(file, 'w') do |f|
        addrs = @addrs.map {|a|
          Hash[[:time, :service, :ip, :port].zip(a.entries)] rescue nil }.compact
        f.write(JSON.pretty_generate(addrs))
      end
      log.info { "Stored #{@addrs.size} addrs to #{file}." }
    rescue
      log.warn { "Error storing addrs to #{file}." }
    end

    def stop
      puts "Shutting down..."
      stop_timers
      EM.stop
    end

    def uptime
      (Time.now - @started).to_i
    end

    def start_timers
      return EM.add_timer(1) { start_timers }  if @importing
      [:queue, :inv_queue, :addrs, :connect, :relay].each do |name|
        interval = @config[:intervals][name].to_f
        next  if !interval || interval == 0.0
        @timers[name] = EM.add_periodic_timer(interval, method("work_#{name}"))
      end
    end

    def stop_timers
      @timers.each {|n, t| EM.cancel_timer t }
    end

    # initiate epoll with given file descriptor and set effective user
    def epoll_init
      log.info { "EPOLL: Available file descriptors: " +
        EM.set_descriptor_table_size(@config[:epoll_limit]).to_s }
      if @config[:epoll_user]
        EM.set_effective_user(@config[:epoll_user])
        log.info { "EPOLL: Effective user set to: #{@config[:epoll_user]}" }
      end
      EM.epoll = true
    end

    def run
      @started = Time.now

      EM.add_shutdown_hook do
        store_addrs
        log.info { "Bye" }
      end

      # enable kqueue (BSD, OS X)
      if EM.kqueue?
        log.info { 'Using BSD kqueue' }
        EM.kqueue = true
      end

      # enable epoll (Linux)
      if EM.epoll?
        log.info { 'Using Linux epoll' }
        epoll_init
      end

      EM.run do

        start_timers

        host, port = *@config[:command]
        port ||= Bitcoin.network[:default_port]
        if host
          log.debug { "Trying to bind command socket to #{host}:#{port}" }
          EM.start_server(host, port, CommandHandler, self)
          log.info { "Command socket listening on #{host}:#{port}" }
        end

        host, port = *@config[:listen]
        port ||= Bitcoin.network[:default_port]
        if host
          log.debug { "Trying to bind server socket to #{host}:#{port}" }
          EM.start_server(host, port.to_i, ConnectionHandler, self, host, port.to_i, :in)
          log.info { "Server socket listening on #{host}:#{port}" }
        end

        @config[:connect].each do |host, port|
          port ||= Bitcoin.network[:default_port]
          connect_peer(host, port)
          log.info { "Connecting to #{host}:#{port}" }
        end

        work_connect if @addrs.any?
        connect_dns  if @config[:dns]

        Signal.trap("INT") do
          puts "Shutting down. You can force-quit by pressing Ctrl-C again, but it might corrupt your database!"
          Signal.trap("INT") do
            puts "Force Quit"
            exit 1
          end
          self.stop
        end

      end
    end

    # connect to peer at given +host+ / +port+
    def connect_peer host, port
      return  if @connections.map{|c| c.host }.include?(host)
      log.debug { "Attempting to connect to #{host}:#{port}" }
      EM.connect(host, port.to_i, ConnectionHandler, self, host, port.to_i, :out)
    rescue
      log.debug { "Error connecting to #{host}:#{port}" }
      log.debug { $!.inspect }
    end

    # query addrs from dns seed and connect
    def connect_dns
      unless Bitcoin.network[:dns_seeds].any?
        log.warn { "No DNS seed nodes available" }
        return connect_known_peers
      end
      connect_dns_resolver(Bitcoin.network[:dns_seeds].sample) do |addrs|
        log.debug { "DNS returned addrs: #{addrs.inspect}" }
        addrs.sample(@config[:max][:connections_out] / 2).uniq.each do |addr|
          connect_peer(addr, Bitcoin.network[:default_port])
        end
      end
    end

    def connect_known_peers
      log.debug { "Attempting to connecting to known nodes" }
      Bitcoin.network[:known_nodes].shuffle[0..3].each do |node|
        connect_peer node, Bitcoin.network[:default_port]
      end
    end

    # get peer addrs from given dns +seed+ using em/dns_resolver.
    # fallback to using `nslookup` if it is not installed or fails.
    def connect_dns_resolver(seed)
      if Bitcoin.require_dependency "em/dns_resolver", gem: "em-dns", exit: false
        log.info { "Querying addresses from DNS seed: #{seed}" }

        dns = EM::DnsResolver.resolve(seed)
        dns.callback {|addrs| yield(addrs) }
        dns.errback do |*a|
          log.error { "Cannot resolve DNS seed #{seed}: #{a.inspect}" }
          connect_dns_nslookup(Bitcoin.network[:dns_seeds].sample) {|a| yield(a) }
        end
      else
        log.info { "Falling back to nslookup resolver." }
        connect_dns_nslookup(seed) {|a| yield(a) }
      end
    end

    # get peers from dns via nslookup
    def connect_dns_nslookup(seed)
      log.info { "Querying addresses from DNS seed: #{seed}" }
      addrs = `nslookup #{seed}`.scan(/Address\: (.+)$/).flatten
      #  exit  if @config[:dns] && hosts.size == 0
      yield(addrs)
    end

    # check if there are enough connections and try to
    # establish new ones if needed
    def work_connect
      log.debug { "Connect worker running" }
      desired = @config[:max][:connections_out] - @connections.select(&:outgoing?).size
      return  if desired <= 0
      desired = 32  if desired > 32 # connect to max 32 peers at once
      if addrs.any?
        addrs.sample(desired) do |addr|
          Time.now.tv_sec + 10800 - addr.time
        end.each do |addr|
          connect_peer(addr.ip, addr.port)
        end
      elsif @config[:dns]
        connect_dns
      end
    rescue
      log.error { "Error during connect: #{$!.inspect}" }
    end

    # query blocks from random peer
    def getblocks locator = store.get_locator
      peer = @connections.select(&:connected?).sample
      return  unless peer
      log.info { "querying blocks from #{peer.host}:#{peer.port}" }
      case @config[:mode]
      when /lite/
        peer.send_getheaders locator  unless @queue.size >= @config[:max][:queue]
      when /full|pruned/
        peer.send_getblocks locator  unless @inv_queue.size >= @config[:max][:inv]
      end
    end

    # check if the addr store is full and request new addrs
    # from a random peer if it isn't
    def work_addrs
      log.debug { "addr worker running" }
      @addrs.delete_if{|addr| !addr.alive? }  if @addrs.size >= @config[:max][:addr]
      return  if !@connections.any? || @config[:max][:connections] <= @connections.size
      connections = @connections.select(&:connected?)
      return  unless connections.any?
      log.info { "requesting addrs" }
      connections.sample.send_getaddr
    end

    # check for new items in the queue and process them
    def work_queue
      @log.debug { "queue worker running" }
      return getblocks  if @queue.size == 0

      # switch off utxo cache once there aren't tons of new blocks coming in
      if @store.in_sync?
        if @store.is_a?(Bitcoin::Storage::Backends::UtxoStore) && @store.config[:utxo_cache] > 0
          log.debug { "switching off utxo cache" }
          @store.config[:utxo_cache] = 0
        end
        @config[:intervals].each do |name, value|
          if value <= 1
            log.debug { "setting #{name} interval to 5 seconds" }
            @config[:intervals][name] = 5
          end
        end
      end

      while obj = @queue.shift
        begin
          if obj[0].to_sym == :block
            if res = @store.send("new_#{obj[0]}", obj[1])
              if res[1] == 0  && obj[1].hash == @store.get_head.hash
                @last_block_time = Time.now
                push_notification(:block, [obj[1], res[0]])
                obj[1].tx.each {|tx| @unconfirmed.delete(tx.hash) }
              end
              getblocks  if res[1] == 2 && @store.in_sync?
            end
          else
            drop = @unconfirmed.size - @config[:max][:unconfirmed] + 1
            drop.times { @unconfirmed.shift }  if drop > 0
            unless @unconfirmed[obj[1].hash]
              @unconfirmed[obj[1].hash] = obj[1]
              push_notification(:tx, [obj[1], 0])

              if @notifiers[:output]
                obj[1].out.each do |out|
                  address = Bitcoin::Script.new(out.pk_script).get_address
                  push_notification(:output, [obj[1].hash, address, out.value, 0])
                end
              end
            end
          end
        rescue Bitcoin::Validation::ValidationError
          @log.warn { "ValiationError storing #{obj[0]} #{obj[1].hash}: #{$!.message}" }
          # File.open("./validation_error_#{obj[0]}_#{obj[1].hash}.bin", "w") {|f|
          #   f.write(obj[1].to_payload) }
          # EM.stop
        rescue
          @log.warn { $!.inspect }
          puts *$@
        end
      end
    end

    # check for new items in the inv queue and process them,
    # unless the queue is already full
    def work_inv_queue
      @log.debug { "inv queue worker running" }
      return  if @inv_queue.size == 0
      return  if @queue.size >= @config[:max][:queue]
      while inv = @inv_queue.shift
        next  if !@store.in_sync? && inv[0] == :tx && @notifiers.empty?
        next  if @queue.map{|i|i[1]}.map(&:hash).include?(inv[1])
        inv[2].send("send_getdata_#{inv[0]}", inv[1])
      end
    end

    # queue inv, caching the most current ones
    def queue_inv inv
      hash = inv[1].unpack("H*")[0]
      return  if @inv_queue.include?(inv) || @queue.select {|i| i[1].hash == hash }.any?

      return  if @store.send("has_#{inv[0]}", hash)

#      @inv_cache.shift(128)  if @inv_cache.size > @config[:max][:inv_cache]
#      return  if @inv_cache.include?([inv[0], inv[1]]) ||
#        @inv_queue.size >= @config[:max][:inv] ||
#        (!@store.in_sync? && inv[0] == :tx)
#      @inv_cache << [inv[0], inv[1]]
      @inv_queue << inv
    end

    def work_relay
      log.debug { "relay worker running" }
      @store.get_unconfirmed_tx.each do |tx|
        relay_tx(tx)
      end
    end

    # get the external ip that was suggested in version messages
    # from other peers most often.
    def external_ip
      @external_ips.group_by(&:dup).values.max_by(&:size).first
    rescue
      @config[:listen][0]
    end

    # push notification +message+ to +channel+
    def push_notification channel, message
      @notifiers[channel.to_sym].push(message)  if @notifiers[channel.to_sym]
    end

    # subscribe to notification +channel+.
    # available channels are: block, tx, output, connection.
    # see CommandHandler for details.
    def subscribe channel
      @notifiers[channel.to_sym] ||= EM::Channel.new
      @notifiers[channel.to_sym].subscribe {|*data| yield(*data) }
    end

    # should the node accept new incoming connections?
    def accept_connections?
      connections.select(&:incoming?).size >= config[:max][:connections_in]
    end

  end
end

class Array
  def random(weights=nil)
    return random(map {|n| yield(n) })  if block_given?
    return random(map {|n| n.send(weights) })  if weights.is_a? Symbol

    weights ||= Array.new(length, 1.0)
    total = weights.inject(0.0) {|t,w| t+w}
    point = rand * total

    zip(weights).each do |n,w|
      return n if w >= point
      point -= w
    end
  end

  def weighted_sample(n, weights = nil)
    src = dup
    buf = []
    n = src.size  if n > src.size
    while buf.size < n
      if block_given?
        item = src.random {|n| yield(n) }
      else
        item = src.random(weights)
      end
      buf << item; src.delete(item)
    end
    buf
  end

  class ::Hash
    def deep_merge(hash)
      target = dup
      hash.keys.each do |key|
        if hash[key].is_a? Hash and self[key].is_a? Hash
          target[key] = target[key].deep_merge(hash[key])
          next
        end
        target[key] = hash[key]
      end
      target
    end
  end

end
