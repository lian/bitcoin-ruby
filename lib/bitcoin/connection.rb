# encoding: ascii-8bit

require 'socket'
require 'eventmachine'
require 'bitcoin'
require 'resolv'

module Bitcoin
  # Handle messages received from node
  module ConnectionHandler
    def on_inv_transaction(hash)
      p ['inv transaction', hash.hth]
      pkt = Protocol.getdata_pkt(:tx, [hash])
      send_data(pkt)
    end

    def on_inv_block(hash)
      p ['inv block', hash.hth]
      pkt = Protocol.getdata_pkt(:block, [hash])
      send_data(pkt)
    end

    def on_get_transaction(hash)
      p ['get transaction', hash.hth]
    end

    def on_get_block(hash)
      p ['get block', hash.hth]
    end

    def on_addr(addr)
      p ['addr', addr, addr.alive?]
    end

    def on_tx(tx)
      p ['tx', tx.hash]
    end

    def on_block(block)
      p ['block', block.hash]
      # p block.payload.each_byte.map{|i| "%02x" % [i] }.join(" ")
      # puts block.to_json
    end

    def on_version(version)
      p [@sockaddr, 'version', version, version.time - Time.now.to_i]
      send_data(Protocol.verack_pkt)
    end

    def on_verack
      on_handshake_complete
    end

    def on_handshake_complete
      p [@sockaddr, 'handshake complete']
      @connected = true

      query_blocks
    end

    def query_blocks
      start = ("\x00" * 32)
      stop  = ("\x00" * 32)
      pkt = Protocol.pkt('getblocks', "\x00" + start + stop)
      send_data(pkt)
    end

    def on_handshake_begin
      block   = 127_953
      from    = '127.0.0.1:8333'
      from_id = Bitcoin::Protocol::Uniq
      to      = @sockaddr.reverse.join(':')
      # p "==", from_id, from, to, block
      pkt = Protocol.version_pkt(from_id, from, to, block)
      p ['sending version pkt', pkt]
      send_data(pkt)
    end
  end

  # Establish connection to node
  class Connection < EM::Connection
    include ConnectionHandler

    def initialize(host, port, connections)
      @sockaddr = [port, host]
      @connections = connections
      @parser = Bitcoin::Protocol::Parser.new(self)
    end

    def post_init
      p ['connected', @sockaddr]
      EM.schedule { on_handshake_begin }
    end

    def receive_data(data)
      @parser.parse(data)
    end

    def unbind
      p ['disconnected', @sockaddr]
      self.class.connect_random_from_dns(@connections)
    end

    def self.connect(host, port, connections)
      EM.connect(host, port, self, host, port, connections)
    end

    def self.connect_random_from_dns(connections)
      seeds = Bitcoin.network[:dns_seeds]
      if seeds.empty?
        raise 'No DNS seeds available. Provide IP, configure seeds, or use different network.'
      end

      host = Resolv::DNS.new.getaddresses(seeds.sample).map(&:to_s).sample
      connect(host, Bitcoin.network[:default_port], connections)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  EM.run do
    connections = []
    # Bitcoin::Connection.connect('127.0.0.1', 8333, connections)
    # Bitcoin::Connection.connect('217.157.1.202', 8333, connections)
    Bitcoin::Connection.connect_random_from_dns(connections)
  end
end
