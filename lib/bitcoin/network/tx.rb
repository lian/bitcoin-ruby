module Bitcoin
  module Protocol

    class Tx
      attr_reader :hash

      def ==(other)
        @hash == other.hash
      end

      def initialize(data)
        parse_data(data) if data
      end

      def parse_data(data)
        @ver, @in_size  = data.unpack("IC")
        raise "unkown transaction version: #{@ver}" unless @ver == 1
        idx = 5

        @in = (0...@in_size).map{
          prev_out, prev_out_index, script_sig_length = data[idx...idx+=37].unpack("a32IC")
          script_sig = data[idx...idx+=script_sig_length]
          seq = data[idx...idx+=4]
          [ prev_out, prev_out_index, script_sig_length, script_sig, seq ]
        }

        @out_size  = data[idx].unpack("C")[0]; idx+=1

        @out = (0...@out_size).map{
          value, pk_script_length = data[idx...idx+=9].unpack("QC")
          pk_script = data[idx...idx+=pk_script_length]
          [ value, pk_script_length, pk_script ]
        }

        @lock_time = data[idx...idx+=4].unpack("I")[0]

        @payload = data[0...idx]
        @hash = Digest::SHA256.digest(Digest::SHA256.digest( @payload )).reverse.unpack("H*")[0]

        if data[idx] == nil
          true          # reached the end.
        else
          data[idx..-1] # rest of buffer.
        end
      end

      def to_hash
        h = {
          'hash' => @hash, 'ver' => @ver,
          'vin_sz' => @in_size, 'vout_sz' => @out_size,
          'lock_time' => @lock_time, 'size' => @payload.size,
          'in' => @in.map{|i|{
            'prev_out'  => { 'hash' => hth(i[0]), 'n' => i[1] },
            'scriptSig' => script_signature_inspect(i[3])
          }},
          'out' => @out.map{|i|{
            'value' => "%.8f" % (i[0] / 100000000.0),
            'scriptPubKey' => pk_script_inspect(i[2])
          }}
        }
        if (i=@in[0]) && i[1] == 4294967295 # coinbase tx
          h['in'][0] = {
            'prev_out'  => { 'hash' => hth(i[0]), 'n' => i[1] },
            'coinbase' => i[3].unpack("H*")[0]
          }
        end
        h
      end

      def hth(s)
        s.reverse.unpack('H*')[0]
      end

      # generates rawblock json as seen in the block explorer.
      def to_json
        JSON.pretty_generate( to_hash )
      end

      def script_signature_inspect(script_sig)
        push_length, stack = script_sig.unpack("Ca*")
        pub, stack = stack.unpack("a#{push_length}a*")
        push_length, stack = stack.unpack("CA*")
        sig, stack = stack.unpack("a#{push_length}a*")
        [pub, sig].map{|i| i.unpack("H*") }.join(" ")
      end

      def pk_script_inspect(pk_script)
        pk_script.unpack("H*")[0]
      end
    end

  end
end
