module Bitcoin
  module Protocol

    class Addr < Struct.new(:time, :service, :ip, :port)

      # create addr from raw binary +data+
      def initialize(data = nil)
        if data
          self[:time], self[:service], self[:ip], self[:port] = data.unpack("IQx12a4n")
          self[:ip] = ip.unpack("C*").join(".")
        end
      end

      # is this address alive?
      def alive?
        (Time.now.tv_sec-7200) <= self[:time]
      end
    end

  end
end
