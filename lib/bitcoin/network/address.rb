module Bitcoin
  module Protocol

    class Addr < Struct.new(:time, :service, :ip, :port)
      def initialize(data)
        self[:time], self[:service], self[:ip], self[:port] = data.unpack("IQx12a4n")
        self[:ip] = ip.unpack("C*").join(".")
      end
      def alive?
        (Time.now.tv_sec-7200) <= self[:time]
      end
    end

  end
end
