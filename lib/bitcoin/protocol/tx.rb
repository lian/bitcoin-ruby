require 'bitcoin/script'

module Bitcoin
  module Protocol

    class Tx

      # transaction hash
      attr_reader :hash

      # inputs (Array of TxIn)
      attr_reader :in

      # outputs (Array of TxOut)
      attr_reader :out

      # raw protocol payload
      attr_reader :payload

      # version (usually 1)
      attr_accessor :ver

      # lock time
      attr_accessor :lock_time

      alias :inputs  :in
      alias :outputs :out

      # compare to another tx
      def ==(other)
        @hash == other.hash
      end

      # return the tx hash in binary format
      def binary_hash
        [@hash].pack("H*").reverse
      end

      # create tx from raw binary +data+
      def initialize(data=nil)
        @ver, @lock_time, @in, @out = 1, 0, [], []
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
        pin  =  @in.map(&:to_payload).join
        pout = @out.map(&:to_payload).join

        in_size, out_size = Protocol.pack_var_int(@in.size), Protocol.pack_var_int(@out.size)
        [[@ver].pack("I"), in_size, pin, out_size, pout, [@lock_time].pack("I")].join
      end

      # generate a signature hash for input +input_idx+.
      # either pass the +outpoint_tx+ or the +script_pubkey+ directly.
      def signature_hash_for_input(input_idx, outpoint_tx, script_pubkey=nil, hash_type=nil, drop_sigs=nil, script=nil)
        # https://github.com/bitcoin/bitcoin/blob/e071a3f6c06f41068ad17134189a4ac3073ef76b/script.cpp#L834
        # http://code.google.com/p/bitcoinj/source/browse/trunk/src/com/google/bitcoin/core/Script.java#318
        # https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
        # https://github.com/bitcoin/bitcoin/blob/c2e8c8acd8ae0c94c70b59f55169841ad195bb99/src/script.cpp#L1058

        hash_type ||= 1 # 1: ALL, 2: NONE, 3: SINGLE

        pin  = @in.map.with_index{|input,idx|
          if idx == input_idx
            script_pubkey ||= outpoint_tx.out[ input.prev_out_index ].pk_script
            script_pubkey = Bitcoin::Script.binary_from_string(script)                if script    # force this string a script
            script_pubkey = Bitcoin::Script.drop_signatures(script_pubkey, drop_sigs) if drop_sigs # array of signature to drop
            input.to_payload(script_pubkey)
          else
            case hash_type
            when 2; input.to_payload("", "\x00\x00\x00\x00")
            else;   input.to_payload("")
            end
          end
        }.join

        pout = @out.map(&:to_payload).join

        case hash_type
        when 2
          pout = ""
          in_size, out_size = Protocol.pack_var_int(@in.size), Protocol.pack_var_int(0)
        else
          in_size, out_size = Protocol.pack_var_int(@in.size), Protocol.pack_var_int(@out.size)
        end

        buf = [ [@ver].pack("I"), in_size, pin, out_size, pout, [@lock_time, hash_type].pack("II") ].join
        Digest::SHA256.digest( Digest::SHA256.digest( buf ) )
      end

      # verify input signature +in_idx+ against the corresponding
      # output in +outpoint_tx+
      def verify_input_signature(in_idx, outpoint_tx)
        outpoint_idx  = @in[in_idx].prev_out_index
        script_sig    = @in[in_idx].script_sig
        script_pubkey = outpoint_tx.out[outpoint_idx].pk_script
        script        = script_sig + script_pubkey

        Bitcoin::Script.new(script).run do |pubkey,sig,hash_type,drop_sigs,script|
          # this IS the checksig callback, must return true/false
          hash = signature_hash_for_input(in_idx, outpoint_tx, nil, hash_type, drop_sigs, script)
          #hash = signature_hash_for_input(in_idx, nil, script_pubkey, hash_type, drop_sigs, script)
          Bitcoin.verify_signature( hash, sig, pubkey.unpack("H*")[0] )
        end
      end

      # convert to ruby hash (see also #from_hash)
      def to_hash
        @hash ||= hash_from_payload(to_payload)
        {
          'hash' => @hash, 'ver' => @ver,
          'vin_sz' => @in.size, 'vout_sz' => @out.size,
          'lock_time' => @lock_time, 'size' => (@payload ||= to_payload).bytesize,
          'in'  =>  @in.map(&:to_hash),
          'out' => @out.map(&:to_hash)
        }
      end

      # generates rawblock json as seen in the block explorer.
      def to_json(options = {:space => ''}, *a)
        JSON.pretty_generate( to_hash, options )
      end

      # write json representation to a file
      # (see also #to_json)
      def to_json_file(path)
        File.open(path, 'wb'){|f| f.print to_json; }
      end

      # parse ruby hash (see also #to_hash)
      def self.from_hash(h)
        tx = new(nil)
        tx.ver, tx.lock_time = *h.values_at('ver', 'lock_time')
        h['in'] .each{|input|   tx.add_in  TxIn.from_hash(input)   }
        h['out'].each{|output|  tx.add_out TxOut.from_hash(output) }
        tx.instance_eval{ @hash = hash_from_payload(@payload = to_payload) }
        tx
      end

      # convert ruby hash to raw binary
      def self.binary_from_hash(h); from_hash(h).to_payload; end

      # parse json representation
      def self.from_json(json_string); from_hash( JSON.load(json_string) ); end

      # convert json representation to raw binary
      def self.binary_from_json(json_string); from_json(json_string).to_payload; end

      # read binary block from a file
      def self.from_file(path); new( Bitcoin::Protocol.read_binary_file(path) ); end

      # read json block from a file
      def self.from_json_file(path); from_json( Bitcoin::Protocol.read_binary_file(path) ); end
    end

  end
end
