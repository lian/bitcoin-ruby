# encoding: ascii-8bit

module Bitcoin
  module Protocol

    class TxOut

      # output value (in base units; "satoshi")
      attr_accessor :value

      # pk_script output Script
      attr_accessor :pk_script, :pk_script_length

      # p2sh redeem script (optional, not included in the serialized binary format)
      attr_accessor :redeem_script

      def initialize *args
        if args.size == 2
          @value, @pk_script_length, @pk_script = args[0], args[1].bytesize, args[1]
        else
          @value, @pk_script_length, @pk_script = *args
        end
      end

      def ==(other)
        @value == other.value && @pk_script == other.pk_script rescue false
      end

      # parse raw binary data for transaction output
      def parse_data(data)
        buf = data.is_a?(String) ? StringIO.new(data) : data
        parse_data_from_io(buf)
        buf.pos
      end

      def self.from_io(buf)
        txout = new; txout.parse_data_from_io(buf); txout
      end

      # parse raw binary data for transaction output
      def parse_data_from_io(buf)
        @value = buf.read(8).unpack("Q")[0]
        @pk_script_length = Protocol.unpack_var_int_from_io(buf)
        @pk_script = buf.read(@pk_script_length)
      end

      alias :parse_payload :parse_data

      def parsed_script
        @parsed_script ||= Bitcoin::Script.new(pk_script)
      end

      def to_payload
        [@value].pack("Q") << Protocol.pack_var_int(@pk_script_length) << @pk_script
      end

      def to_null_payload
        self.class.new(-1, '').to_payload
      end

      def to_hash(options = {})
        h = { 'value' => "%.8f" % (@value / 100000000.0),
          'scriptPubKey' => parsed_script.to_string }
        h["address"] = parsed_script.get_address  if parsed_script.is_hash160? && options[:with_address]
        h
      end

      def self.from_hash(output)
        amount = output['value'].gsub('.','').to_i
        script = Script.binary_from_string(output['scriptPubKey'])
        new(amount, script)
      end

      # set pk_script and pk_script_length
      def pk_script=(pk_script)
        @pk_script_length, @pk_script = pk_script.bytesize, pk_script
      end

      alias :amount   :value
      alias :amount=  :value=

      alias :script   :pk_script
      alias :script=  :pk_script=

      # create output spending +value+ btc (base units) to +address+
      def self.value_to_address(value, address)
        pk_script = Bitcoin::Script.to_address_script(address)
        raise "Script#pk_script nil with address #{address}" unless pk_script
        new(value, pk_script)
      end

    end

  end
end
