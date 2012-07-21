module Bitcoin
  module Protocol

    class TxOut

      # output value (in base units; "satoshi")
      attr_accessor :value

      # pk_script output Script
      attr_accessor :pk_script, :pk_script_length

      def initialize *args
        if args.size == 2
          @value, @pk_script_length, @pk_script = args[0], args[1].bytesize, args[1]
        else
          @value, @pk_script_length, @pk_script = *args
        end
      end

      def ==(other)
        @value == other.value && @pk_script == other.pk_script
      end

      # parse raw binary data for transaction output
      def parse_data(data)
        idx = 0
        @value = data[idx...idx+=8].unpack("Q")[0]
        @pk_script_length, tmp = Protocol.unpack_var_int(data[idx..-1])
        idx += data[idx..-1].bytesize - tmp.bytesize
        @pk_script = data[idx...idx+=@pk_script_length]
        idx
      end

      # set pk_script and pk_script_length
      def pk_script=(script)
        @pk_script_length, @pk_script = script.bytesize, script
      end

      alias :amount   :value
      alias :amount=  :value=
      alias :script   :pk_script
      alias :script=  :pk_script=


      # create output spending +value+ btc (base units) to +address+
      def self.value_to_address(value, address)
        pk_script = Bitcoin::Script.to_address_script(address)
        new(value, pk_script)
      end

    end

  end
end
