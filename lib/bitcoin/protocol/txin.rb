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

    end

  end
end
