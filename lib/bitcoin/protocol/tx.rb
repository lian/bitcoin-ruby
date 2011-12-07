require 'bitcoin/script'

module Bitcoin
  module Protocol

    class Tx
      attr_reader :hash, :in, :out, :payload
      attr_accessor :ver, :lock_time

      # compare to another tx
      def ==(other)
        @hash == other.hash
      end

      # return the tx hash in binary format
      def binary_hash
        [@hash].pack("H*").reverse
      end

      # create tx from raw binary +data+
      def initialize(data)
        @ver, @lock_time = 1, 0

        parse_data(data) if data
      end

      # generate the tx hash for given +payload+ in hex format
      def hash_from_payload(payload)
        Digest::SHA256.digest(Digest::SHA256.digest( payload )).reverse.unpack("H*")[0]
      end
      alias generate_hash hash_from_payload

      # add an input
      def add_in(input); (@in ||= []) << input; end

      # add an output
      def add_out(output); (@out ||= []) << output; end

      # parse raw binary data
      def parse_data(data)
        @ver = data.unpack("I")[0]
        idx = 4
        in_size, tmp = Protocol.unpack_var_int(data[idx..-1])
        idx += data[idx..-1].bytesize-tmp.bytesize
        # raise "unkown transaction version: #{@ver}" unless @ver == 1

        @in = (0...in_size).map{
          txin = TxIn.new
          idx += txin.parse_data(data[idx..-1])
          txin
        }

        out_size, tmp = Protocol.unpack_var_int(data[idx..-1])
        idx += data[idx..-1].bytesize-tmp.bytesize

        @out = (0...out_size).map{
          txout = TxOut.new
          idx += txout.parse_data(data[idx..-1])
          txout
        }

        @lock_time = data[idx...idx+=4].unpack("I")[0]

        @payload = data[0...idx]
        @hash = hash_from_payload(@payload)

        if data[idx] == nil
          true          # reached the end.
        else
          data[idx..-1] # rest of buffer.
        end
      end

      # output transaction in raw binary format
      def to_payload
        pin = @in.map{|i|
          buf =  [ i.prev_out, i.prev_out_index ].pack("a32I")
          buf << Protocol.pack_var_int(i.script_sig_length)
          buf << i.script_sig if i.script_sig_length > 0
          buf << "\xff\xff\xff\xff" # sequence
        }.join

        pout = @out.map{|o|
          buf =  [ o.value ].pack("Q")
          buf << Protocol.pack_var_int(o.pk_script_length)
          buf << o.pk_script if o.pk_script_length > 0
          buf
        }.join

        in_size, out_size = Protocol.pack_var_int(@in.size), Protocol.pack_var_int(@out.size)
        [[@ver].pack("I"), in_size, pin, out_size, pout, [@lock_time].pack("I")].join
      end

      # generate a signature hash for input +input_idx+.
      # either pass the +outpoint_tx+ or the +script_pubkey+ directly.
      def signature_hash_for_input(input_idx, outpoint_tx, script_pubkey=nil)
        # https://github.com/bitcoin/bitcoin/blob/e071a3f6c06f41068ad17134189a4ac3073ef76b/script.cpp#L834
        # http://code.google.com/p/bitcoinj/source/browse/trunk/src/com/google/bitcoin/core/Script.java#318
        pin  = @in.map.with_index{|i,idx|
          if idx == input_idx
            script_pubkey ||= outpoint_tx.out[ i.prev_out_index ].pk_script
            length = script_pubkey.bytesize
            [ i.prev_out, i.prev_out_index, length, script_pubkey, "\xff\xff\xff\xff" ].pack("a32ICa#{length}a4")
          else
            [ i.prev_out, i.prev_out_index, 0, "\xff\xff\xff\xff" ].pack("a32ICa4")
          end
        }.join
        pout = @out.map{|o|
          [ o.value, o.pk_script_length, o.pk_script ].pack("QCa#{o.pk_script_length}")
        }.join

        hash_type = 1 # 1: ALL, 2: NONE, 3: SINGLE

        in_size, out_size = Protocol.pack_var_int(@in.size), Protocol.pack_var_int(@out.size)
        buf = [[@ver].pack("I"), in_size, pin, out_size, pout, [@lock_time].pack("I")].join + [hash_type].pack("I")
        Digest::SHA256.digest( Digest::SHA256.digest( buf ) )
      end

      # verify input signature +in_idx+ against the corresponding
      # output in +outpoint_tx+
      def verify_input_signature(in_idx, outpoint_tx)
        outpoint_idx  = @in[in_idx].prev_out_index
        script_sig    = @in[in_idx].script_sig
        script_pubkey = outpoint_tx.out[outpoint_idx].pk_script
        script        = script_sig + script_pubkey

        Bitcoin::Script.new(script).run do |pubkey,sig,hash_type|
          # this IS the checksig callback, must return true/false
          #p ['checksig', pubkey, sig, hash_type]
          hash = signature_hash_for_input(in_idx, outpoint_tx)
          #hash = signature_hash_for_input(in_idx, nil, script_pubkey)
          Bitcoin.verify_signature( hash, sig, pubkey.unpack("H*")[0] )
        end
      end

      # convert to ruby hash (see also #from_hash)
      def to_hash
        h = {
          'hash' => @hash, 'ver' => @ver,
          'vin_sz' => @in.size, 'vout_sz' => @out.size,
          'lock_time' => @lock_time, 'size' => (@payload ||= to_payload).bytesize,
          'in' => @in.map{|i|{
            'prev_out'  => { 'hash' => hth(i.prev_out), 'n' => i.prev_out_index },
            'scriptSig' => Bitcoin::Script.new(i.script_sig).to_string
          }},
          'out' => @out.map{|o|{
            'value' => "%.8f" % (o.value / 100000000.0),
            'scriptPubKey' => Bitcoin::Script.new(o.pk_script).to_string
          }}
        }
        if (i=@in[0]) && i.prev_out_index == 4294967295 # coinbase tx
          h['in'][0] = {
            'prev_out'  => { 'hash' => hth(i.prev_out), 'n' => i.prev_out_index },
            'coinbase' => i.script_sig.unpack("H*")[0]
          }
        end
        h
      end

      def hth(s)
        s.reverse.unpack('H*')[0]
      end

      # generates rawblock json as seen in the block explorer.
      def to_json
        JSON.pretty_generate( to_hash, :space => '' )
      end

      # parse ruby hash (see also #to_hash)
      def self.from_hash(h)
        tx = new(nil)
        tx.ver, tx.lock_time = *h.values_at('ver', 'lock_time')
        h['in'].each{|input|
          txin = TxIn.new(htb(input['prev_out']['hash']), input['prev_out']['n'])

          if input['coinbase']
            coinbase_data = [ input['coinbase'] ].pack("H*")
            txin.script_sig_length = coinbase_data.bytesize
            txin.script_sig = coinbase_data
          else
            script_data = Script.binary_from_string(input['scriptSig'])
            txin.script_sig_length = script_data.bytesize
            txin.script_sig = script_data
          end
          # txin.sequence = ??
          tx.add_in(txin)
        }
        h['out'].each{|output|
          value = output['value'].gsub('.','').to_i
          script_data = Script.binary_from_string(output['scriptPubKey'])
          tx.add_out( TxOut.new(value, script_data.bytesize, script_data) )

        }
        tx.instance_eval{ @hash = hash_from_payload(@payload = to_payload) }
        tx
      end

      # convert ruby hash to raw binary
      def self.binary_from_hash(h); from_hash(h).to_payload; end

      # parse json representation
      def self.from_json(json_string); from_hash( JSON.load(json_string) ); end

      # convert json representation to raw binary
      def self.binary_from_json(json_string); from_json(json_string).to_payload; end

      def self.htb(s)
        [s].pack('H*').reverse
      end
    end

  end
end
