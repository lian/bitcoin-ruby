module Bitcoin
  module Protocol

    class Addr < Struct.new(:time, :service, :ip, :port)

      # create addr from raw binary +data+
      def initialize(data = nil)
        if data
          self[:time], self[:service], self[:ip], self[:port] = data.unpack("IQx12a4n")
          self[:ip] = ip.unpack("C*").join(".")
        else
          self[:time], self[:service] = Time.now.to_i, 1
          self[:ip], self[:port] = "127.0.0.1", Bitcoin.network[:default_port]
        end
      end

      # is this address alive?
      def alive?
        (Time.now.tv_sec-7200) <= self[:time]
      end

      def to_payload
        ip = self[:ip].split(".").map(&:to_i)
        [ time, service, ("\x00"*10)+"\xff\xff", *ip, port ].pack("IQa12C4n")
      end

      def self.pkt(*addrs)
        addrs = addrs.select{|i| i.is_a?(Bitcoin::Protocol::Addr) }
        length = Bitcoin::Protocol.pack_var_int(addrs.size)
        Bitcoin::Protocol.pkt("addr", length + addrs.map(&:to_payload).join)
      end
    end

  end
end
