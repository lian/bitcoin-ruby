module Bitcoin
  module Protocol

    class TxIn

      # previous output hash
      attr_accessor :prev_out

      # previous output index
      attr_accessor :prev_out_index

      # script_sig input Script (signature)
      attr_accessor :script_sig, :script_sig_length

      # sequence
      attr_accessor :sequence

      DEFAULT_SEQUENCE = "\xff\xff\xff\xff"

      def initialize *args
        @prev_out, @prev_out_index, @script_sig_length,
        @script_sig, @sequence = *args
        @sequence ||= DEFAULT_SEQUENCE
      end

      # compare to another txout
      def ==(other)
        @prev_out == other.prev_out &&
          @prev_out_index == other.prev_out_index &&
          @script_sig == other.script_sig &&
          @sequence == other.sequence
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

      alias :parse_payload :parse_data

      def to_payload(script=@script_sig, sequence=@sequence)
        buf =  [ @prev_out, @prev_out_index ].pack("a32I")
        buf << Protocol.pack_var_int(script.bytesize)
        buf << script if script.bytesize > 0
        buf << (sequence || DEFAULT_SEQUENCE)
      end

      def to_hash
        t = { 'prev_out'  => { 'hash' => @prev_out.reverse.unpack("H*")[0], 'n' => @prev_out_index } }
        if coinbase?
          t['coinbase']  = @script_sig.unpack("H*")[0]
        else # coinbase tx
          t['scriptSig'] = Bitcoin::Script.new(@script_sig).to_string
          t['sequence']  = @sequence.unpack("I")[0] unless @sequence == "\xff\xff\xff\xff"
        end
        t
      end

      def self.from_hash(input)
        txin = TxIn.new([ input['prev_out']['hash'] ].pack('H*').reverse, input['prev_out']['n'])
        if input['coinbase']
          txin.script_sig = [ input['coinbase'] ].pack("H*")
          txin.sequence = "\xff\xff\xff\xff"
        else
          txin.script_sig = Script.binary_from_string(input['scriptSig'])
          txin.sequence = [ input['sequence'] || 0xffffffff ].pack("I")
        end
        txin
      end

      # previous output in hex
      def previous_output
        @prev_out.reverse.unpack("H*")[0]
      end

      # check if input is coinbase
      def coinbase?
        (@prev_out_index == 4294967295) && (@prev_out == "\x00"*32)
      end

      # set script_sig and script_sig_length
      def script_sig=(script_sig)
        @script_sig_length = script_sig.bytesize
        @script_sig = script_sig
      end
      alias :script= :script_sig=

    end

  end
end
