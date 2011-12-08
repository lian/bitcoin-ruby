module Bitcoin
  module Protocol

    class TxIn

      attr_accessor :prev_out, :prev_out_index, :script_sig_length, :script_sig, :sequence

      def initialize *args
        @prev_out, @prev_out_index, @script_sig_length,
        @script_sig, @sequence = *args
      end

      def [] idx
        case idx
        when 0 then @prev_out
        when 1 then @prev_out_index
        when 2 then @script_sig_length
        when 3 then @script_sig
        when 4 then @sequence
        end
      end

      def []= idx, val
        case idx
        when 0 then @prev_out = val
        when 1 then @prev_out_index = val
        when 2 then @script_sig_length = val
        when 3 then @script_sig = val
        when 4 then @sequence = val
        end
      end

      # parse raw binary data for transaction input
      def parse_data(data)
        idx = 0
        @prev_out, @prev_out_index = data[idx...idx+=36].unpack("a32I")
        @script_sig_length, tmp = Protocol.unpack_var_int(data[idx..-1])
        idx += data[idx..-1].bytesize - tmp.bytesize
        @script_sig = data[idx...idx+=@script_sig_length]
        @sequence = data[idx...idx+=4]
        idx
      end

      # previous output in hex
      def previous_output
        @prev_out.reverse.unpack("H*")[0]
      end

      def coinbase?
        (@prev_out_index == 4294967295) && (@prev_out == "\x00"*32)
      end

    end

  end
end
