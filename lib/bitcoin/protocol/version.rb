# encoding: ascii-8bit

module Bitcoin
  module Protocol
    # https://en.bitcoin.it/wiki/Protocol_specification#version
    class Version
      # services bit constants
      NODE_NONE = 0
      NODE_NETWORK = (1 << 0)

      attr_reader :fields

      def initialize(opts = {})
        @fields = {
          version: Bitcoin.network[:protocol_version],
          services: NODE_NETWORK,
          time: Time.now.tv_sec,
          from: '127.0.0.1:8333',
          to: '127.0.0.1:8333',
          nonce: Bitcoin::Protocol::Uniq,
          user_agent: "/bitcoin-ruby:#{Bitcoin::VERSION}/",
          last_block: 0, # 188617
          relay: true # BIP0037
        }.merge(opts.reject { |_k, v| v.nil? })
      end

      def to_payload
        [
          @fields.values_at(:version, :services, :time).pack('VQQ'),
          pack_address_field(@fields[:from]),
          pack_address_field(@fields[:to]),
          @fields.values_at(:nonce).pack('Q'),
          Protocol.pack_var_string(@fields[:user_agent]),
          @fields.values_at(:last_block).pack('V'),
          # Satoshi 0.8.6 doesn't send this but it does respect it
          Protocol.pack_boolean(@fields[:relay])
        ].join
      end

      def to_pkt
        Bitcoin::Protocol.pkt('version', to_payload)
      end

      def parse(payload)
        version, services, timestamp, to, from, nonce, payload = payload.unpack('VQQa26a26Qa*')
        to = unpack_address_field(to)
        from = unpack_address_field(from)
        user_agent, payload = Protocol.unpack_var_string(payload)
        last_block, payload = payload.unpack('Va*')
        relay, = unpack_relay_field(version, payload)

        @fields = {
          version: version, services: services, time: timestamp,
          from: from, to: to, nonce: nonce,
          user_agent: user_agent.to_s, last_block: last_block, relay: relay
        }
        self
      end

      def unpack_address_field(payload)
        ip, port = payload.unpack('x8x12a4n')
        "#{ip.unpack('C*').join('.')}:#{port}"
      end

      def pack_address_field(addr_str)
        host, port = addr_str.split(':')
        port = port ? port.to_i : 8333
        sockaddr = Socket.pack_sockaddr_in(port, host)
        # raise "invalid IPv4 Address: #{addr}" unless sockaddr[0...2] == "\x02\x00"
        port = sockaddr[2...4]
        host = sockaddr[4...8]
        [[1].pack('Q'), "\x00" * 10, "\xFF\xFF", host, port].join
      end

      # BIP0037: this field starts with version 70001 and is allowed to be missing, defaults to true
      def unpack_relay_field(version, payload)
        version >= 70_001 && payload ? Protocol.unpack_boolean(payload) : [true, nil]
      end

      def uptime
        @fields[:time] - Time.now.tv_sec
      end

      def method_missing(*a)
        @fields[a.first]
      rescue StandardError
        super
      end

      def respond_to_missing?(*a)
        @fields[a.first]
      rescue StandardError
        super
      end

      def self.parse(payload)
        new.parse(payload)
      end
    end
  end
end
