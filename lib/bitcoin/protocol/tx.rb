# encoding: ascii-8bit

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
        parse_data_from_io(data) if data
      end

      # generate the tx hash for given +payload+ in hex format
      def hash_from_payload(payload)
        Digest::SHA256.digest(Digest::SHA256.digest( payload )).reverse_hth
      end
      alias generate_hash hash_from_payload

      # add an input
      def add_in(input); (@in ||= []) << input; end

      # add an output
      def add_out(output); (@out ||= []) << output; end

      # parse raw binary data
      def parse_data_from_io(data)
        buf = data.is_a?(String) ? StringIO.new(data) : data
        payload_start = buf.pos

        @ver = buf.read(4).unpack("V")[0]

        in_size = Protocol.unpack_var_int_from_io(buf)
        @in = []
        in_size.times{ @in << TxIn.from_io(buf) }

        out_size = Protocol.unpack_var_int_from_io(buf)
        @out = []
        out_size.times{ @out << TxOut.from_io(buf) }

        @lock_time = buf.read(4).unpack("V")[0]

        payload_end = buf.pos;
        buf.seek(payload_start)
        @payload = buf.read( payload_end-payload_start )
        @hash = hash_from_payload(@payload)

        if buf.eof?
          true
        else
          data.is_a?(StringIO) ? buf : buf.read
        end
      end

      alias :parse_data  :parse_data_from_io

      # output transaction in raw binary format
      def to_payload
        pin = ""
        @in.each{|input| pin << input.to_payload }
        pout = ""
        @out.each{|output| pout << output.to_payload }

        [@ver].pack("V") << Protocol.pack_var_int(@in.size) << pin << Protocol.pack_var_int(@out.size) << pout << [@lock_time].pack("V")
      end


      SIGHASH_TYPE = { all: 1, none: 2, single: 3, anyonecanpay: 128 }

      # generate a signature hash for input +input_idx+.
      # either pass the +outpoint_tx+ or the +script_pubkey+ directly.
      def signature_hash_for_input(input_idx, outpoint_tx, script_pubkey=nil, hash_type=nil, drop_sigs=nil, script=nil)
        # https://github.com/bitcoin/bitcoin/blob/e071a3f6c06f41068ad17134189a4ac3073ef76b/script.cpp#L834
        # http://code.google.com/p/bitcoinj/source/browse/trunk/src/com/google/bitcoin/core/Script.java#318
        # https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
        # https://github.com/bitcoin/bitcoin/blob/c2e8c8acd8ae0c94c70b59f55169841ad195bb99/src/script.cpp#L1058
        # https://en.bitcoin.it/wiki/OP_CHECKSIG

        return "\x01".ljust(32, "\x00") if input_idx >= @in.size # ERROR: SignatureHash() : input_idx=%d out of range

        hash_type ||= SIGHASH_TYPE[:all]

        pin  = @in.map.with_index{|input,idx|
          if idx == input_idx
            script_pubkey ||= outpoint_tx.out[ input.prev_out_index ].pk_script
            script_pubkey = script                                                    if script    # force binary aa script
            script_pubkey = Bitcoin::Script.drop_signatures(script_pubkey, drop_sigs) if drop_sigs # array of signature to drop (slow)
            #p Bitcoin::Script.new(script_pubkey).to_string
            input.to_payload(script_pubkey)
          else
            case (hash_type & 0x1f)
            when SIGHASH_TYPE[:none];   input.to_payload("", "\x00\x00\x00\x00")
            when SIGHASH_TYPE[:single]; input.to_payload("", "\x00\x00\x00\x00")
            else;                       input.to_payload("")
            end
          end
        }

        pout = @out.map(&:to_payload)
        in_size, out_size = Protocol.pack_var_int(@in.size), Protocol.pack_var_int(@out.size)

        case (hash_type & 0x1f)
        when SIGHASH_TYPE[:none]
          pout = ""
          out_size = Protocol.pack_var_int(0)
        when SIGHASH_TYPE[:single]
          return "\x01".ljust(32, "\x00") if input_idx >= @out.size # ERROR: SignatureHash() : input_idx=%d out of range (SIGHASH_SINGLE)
          pout = @out[0...(input_idx+1)].map.with_index{|out,idx| (idx==input_idx) ? out.to_payload : out.to_null_payload }.join
          out_size = Protocol.pack_var_int(input_idx+1)
        end

        if (hash_type & SIGHASH_TYPE[:anyonecanpay]) != 0
          in_size, pin = Protocol.pack_var_int(1), [ pin[input_idx] ]
        end

        buf = [ [@ver].pack("V"), in_size, pin, out_size, pout, [@lock_time, hash_type].pack("VV") ].join
        Digest::SHA256.digest( Digest::SHA256.digest( buf ) )
      end

      # verify input signature +in_idx+ against the corresponding
      # output in +outpoint_tx+
      def verify_input_signature(in_idx, outpoint_tx, block_timestamp=Time.now.to_i)
        outpoint_idx  = @in[in_idx].prev_out_index
        script_sig    = @in[in_idx].script_sig
        script_pubkey = outpoint_tx.out[outpoint_idx].pk_script
        script        = script_sig + script_pubkey

        Bitcoin::Script.new(script).run(block_timestamp) do |pubkey,sig,hash_type,drop_sigs,script|
          # this IS the checksig callback, must return true/false
          hash = signature_hash_for_input(in_idx, outpoint_tx, nil, hash_type, drop_sigs, script)
          #hash = signature_hash_for_input(in_idx, nil, script_pubkey, hash_type, drop_sigs, script)
          Bitcoin.verify_signature( hash, sig, pubkey.unpack("H*")[0] )
        end
      end

      # convert to ruby hash (see also #from_hash)
      def to_hash(options = {})
        @hash ||= hash_from_payload(to_payload)
        h = {
          'hash' => @hash, 'ver' => @ver, # 'nid' => normalized_hash,
          'vin_sz' => @in.size, 'vout_sz' => @out.size,
          'lock_time' => @lock_time, 'size' => (@payload ||= to_payload).bytesize,
          'in'  =>  @in.map{|i| i.to_hash(options) },
          'out' => @out.map{|o| o.to_hash(options) }
        }
        h
      end

      # generates rawblock json as seen in the block explorer.
      def to_json(options = {:space => ''}, *a)
        JSON.pretty_generate( to_hash(options), options )
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

      def validator(store, block = nil)
        @validator ||= Bitcoin::Validation::Tx.new(self, store, block)
      end

      def size
        payload.bytesize
      end

      DEFAULT_BLOCK_PRIORITY_SIZE = 27000

      def minimum_relay_fee; calculate_minimum_fee(allow_free=true, :relay); end
      def minimum_block_fee; calculate_minimum_fee(allow_free=true, :block); end

      def calculate_minimum_fee(allow_free=true, mode=:block)
        # Base fee is either nMinTxFee or nMinRelayTxFee
        base_fee  = (mode == :relay) ? Bitcoin.network[:min_relay_tx_fee] : Bitcoin.network[:min_tx_fee]
        tx_size   = to_payload.bytesize
        min_fee   = (1 + tx_size / 1_000) * base_fee

        if allow_free
          # There is a free transaction area in blocks created by most miners,
          # * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
          #   to be considered to fall into this category. We don't want to encourage sending
          #   multiple transactions instead of one big transaction to avoid fees.
          # * If we are creating a transaction we allow transactions up to 1,000 bytes
          #   to be considered safe and assume they can likely make it into this section.
          min_fee = 0 if tx_size < (mode == :block ? 1_000 : DEFAULT_BLOCK_PRIORITY_SIZE - 1_000)
        end

        # This code can be removed after enough miners have upgraded to version 0.9.
        # Until then, be safe when sending and require a fee if any output is less than CENT
        if min_fee < base_fee && mode == :block
          outputs.each{|output| (min_fee = base_fee; break) if output.value < Bitcoin::CENT }
        end

        min_fee = Bitcoin::network[:max_money] unless min_fee.between?(0, Bitcoin::network[:max_money])
        min_fee
      end

      def is_coinbase?
        inputs.size == 1 and inputs.first.coinbase?
      end

      def normalized_hash
        signature_hash_for_input(-1, nil, nil, SIGHASH_TYPE[:all]).unpack("H*")[0]
      end

    end
  end
end
