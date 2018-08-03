# encoding: ascii-8bit

module Bitcoin
  module Protocol
    Addr = Struct.new(:time, :service, :ip, :port) do
      # # IP Address / Port
      # attr_reader :ip, :port

      # # Time the node was last active
      # attr_reader :time

      # # Services supported by this node
      # attr_reader :service

      # create addr from raw binary +data+
      def initialize(data = nil)
        if data
          unpacked = data.unpack('VQx12a4n')
          self[:time], self[:service], self[:ip], self[:port] = unpacked
          self[:ip] = ip.unpack('C*').join('.')
        else
          self[:time] = Time.now.to_i
          self[:service] = 1
          self[:ip] = '127.0.0.1'
          self[:port] = Bitcoin.network[:default_port]
        end
      end

      # is this address alive?
      def alive?
        (Time.now.tv_sec - 7200) <= self[:time]
      end

      def to_payload
        ip = self[:ip].split('.').map(&:to_i)
        [time, service, ("\x00" * 10) + "\xff\xff", *ip, port].pack('VQa12C4n')
      end

      def string
        "#{self[:ip]}:#{self[:port]}"
      end

      def self.pkt(*addrs)
        addrs = addrs.select do |i|
          i.is_a?(Bitcoin::Protocol::Addr) && i.ip =~ /^\d+\.\d+\.\d+\.\d+$/
        end
        length = Bitcoin::Protocol.pack_var_int(addrs.size)
        Bitcoin::Protocol.pkt('addr', length + addrs.map(&:to_payload).join)
      end
    end
  end
end
