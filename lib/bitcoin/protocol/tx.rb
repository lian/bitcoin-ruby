# encoding: ascii-8bit

require 'bitcoin/script'

module Bitcoin
  module Protocol

    class Tx

      MARKER = 0
      FLAG = 1

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

      # parsed / evaluated input scripts cached for later use
      attr_reader :scripts

      attr_accessor :marker
      attr_accessor :flag

      alias :inputs  :in
      alias :outputs :out

      # compare to another tx
      def ==(other)
        @hash == other.hash
      end

      # return the tx hash in binary format
      def binary_hash
        @binary_hash ||= [@hash].pack("H*").reverse
      end

      # create tx from raw binary +data+
      def initialize(data=nil)
        @ver, @lock_time, @in, @out, @scripts = 1, 0, [], [], []
        @enable_bitcoinconsensus = !!ENV['USE_BITCOINCONSENSUS']
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

        @ver = buf.read(4).unpack("V")[0]

        return false if buf.eof?

        in_size = Protocol.unpack_var_int_from_io(buf)

        # segwit serialization format is defined by https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
        witness = false
        if in_size.zero?
          @marker = 0
          @flag = buf.read(1).unpack('c').first
          in_size = Protocol.unpack_var_int_from_io(buf)
          witness = true
        end

        @in = []
        in_size.times{
          break if buf.eof?
          @in << TxIn.from_io(buf)
        }

        return false if buf.eof?

        out_size = Protocol.unpack_var_int_from_io(buf)
        @out = []
        out_size.times{
          break if buf.eof?
          @out << TxOut.from_io(buf)
        }

        return false if buf.eof?

        if witness
          in_size.times do |i|
            witness_count = Protocol.unpack_var_int_from_io(buf)
            witness_count.times do
              size = Protocol.unpack_var_int_from_io(buf)
              @in[i].script_witness.stack << buf.read(size)
            end
          end
        end

        @lock_time = buf.read(4).unpack("V")[0]

        @hash = hash_from_payload(to_old_payload)

        if buf.eof?
          true
        else
          data.is_a?(StringIO) ? buf : buf.read
        end
      end

      alias :parse_data  :parse_data_from_io

      # output transaction in raw binary format
      def to_payload
        witness? ? to_witness_payload : to_old_payload
      end

      def to_old_payload
        pin = ""
        @in.each{|input| pin << input.to_payload }
        pout = ""
        @out.each{|output| pout << output.to_payload }

        [@ver].pack("V") << Protocol.pack_var_int(@in.size) << pin << Protocol.pack_var_int(@out.size) << pout << [@lock_time].pack("V")
      end

      # output transaction in raw binary format with witness
      def to_witness_payload
        buf = [@ver, MARKER, FLAG].pack('Vcc')
        buf << Protocol.pack_var_int(@in.length) << @in.map(&:to_payload).join
        buf << Protocol.pack_var_int(@out.length) << @out.map(&:to_payload).join
        buf << witness_payload << [@lock_time].pack('V')
        buf
      end

      def witness_payload
        @in.map { |i| i.script_witness.to_payload }.join
      end

      def witness?
        !@in.find { |i| !i.script_witness.empty? }.nil?
      end

      SIGHASH_TYPE = { all: 1, none: 2, single: 3, anyonecanpay: 128 }

      # generate a signature hash for input +input_idx+.
      # either pass the +outpoint_tx+ or the +script_pubkey+ directly.
      def signature_hash_for_input(input_idx, subscript, hash_type=nil)
        # https://github.com/bitcoin/bitcoin/blob/e071a3f6c06f41068ad17134189a4ac3073ef76b/script.cpp#L834
        # http://code.google.com/p/bitcoinj/source/browse/trunk/src/com/google/bitcoin/core/Script.java#318
        # https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
        # https://github.com/bitcoin/bitcoin/blob/c2e8c8acd8ae0c94c70b59f55169841ad195bb99/src/script.cpp#L1058
        # https://en.bitcoin.it/wiki/OP_CHECKSIG

        # Note: BitcoinQT checks if input_idx >= @in.size and returns 1 with an error message.
        # But this check is never actually useful because BitcoinQT would crash 
        # right before VerifyScript if input index is out of bounds (inside CScriptCheck::operator()()).
        # That's why we don't need to do such a check here.
        #
        # However, if you look at the case SIGHASH_TYPE[:single] below, we must 
        # return 1 because it's possible to have more inputs than outputs and BitcoinQT returns 1 as well.
        return "\x01".ljust(32, "\x00") if input_idx >= @in.size # ERROR: SignatureHash() : input_idx=%d out of range

        hash_type ||= SIGHASH_TYPE[:all]

        pin  = @in.map.with_index{|input,idx|
          if idx == input_idx
            subscript = subscript.out[ input.prev_out_index ].script if subscript.respond_to?(:out) # legacy api (outpoint_tx)
            input.to_payload(subscript)
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

      # generate a witness signature hash for input +input_idx+.
      # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
      def signature_hash_for_witness_input(input_idx, witness_program, prev_out_value, witness_script = nil, hash_type=nil, skip_separator_index = 0)
        return "\x01".ljust(32, "\x00") if input_idx >= @in.size # ERROR: SignatureHash() : input_idx=%d out of range

        hash_type ||= SIGHASH_TYPE[:all]

        script = Bitcoin::Script.new(witness_program)
        raise "ScriptPubkey does not contain witness program." unless script.is_witness?

        hash_prevouts = Digest::SHA256.digest(Digest::SHA256.digest(@in.map{|i| [i.prev_out_hash, i.prev_out_index].pack("a32V")}.join))
        hash_sequence = Digest::SHA256.digest(Digest::SHA256.digest(@in.map{|i|i.sequence}.join))
        outpoint = [@in[input_idx].prev_out_hash, @in[input_idx].prev_out_index].pack("a32V")
        amount = [prev_out_value].pack("Q")
        nsequence = @in[input_idx].sequence

        if script.is_witness_v0_keyhash?
          script_code = [["1976a914", script.get_hash160, "88ac"].join].pack("H*")
        elsif script.is_witness_v0_scripthash?
          raise "witness script does not match script pubkey" unless Bitcoin::Script.to_witness_p2sh_script(Digest::SHA256.digest(witness_script).bth) == witness_program
          script = skip_separator_index > 0 ? Bitcoin::Script.new(witness_script).subscript_codeseparator(skip_separator_index) : witness_script
          script_code = Bitcoin::Protocol.pack_var_string(script)
        end

        hash_outputs = Digest::SHA256.digest(Digest::SHA256.digest(@out.map{|o|o.to_payload}.join))

        case (hash_type & 0x1f)
          when SIGHASH_TYPE[:single]
            hash_outputs = input_idx >= @out.size ? "\x00".ljust(32, "\x00") : Digest::SHA256.digest(Digest::SHA256.digest(@out[input_idx].to_payload))
            hash_sequence = "\x00".ljust(32, "\x00")
          when SIGHASH_TYPE[:none]
            hash_sequence = hash_outputs = "\x00".ljust(32, "\x00")
        end

        if (hash_type & SIGHASH_TYPE[:anyonecanpay]) != 0
          hash_prevouts = hash_sequence ="\x00".ljust(32, "\x00")
        end

        buf = [ [@ver].pack("V"), hash_prevouts, hash_sequence, outpoint,
                script_code, amount, nsequence, hash_outputs, [@lock_time, hash_type].pack("VV")].join

        Digest::SHA256.digest( Digest::SHA256.digest( buf ) )
      end

      # verify input signature +in_idx+ against the corresponding
      # output in +outpoint_tx+
      # outpoint
      #
      # options are: verify_sigpushonly, verify_minimaldata, verify_cleanstack, verify_dersig, verify_low_s, verify_strictenc
      def verify_input_signature(in_idx, outpoint_tx_or_script, block_timestamp=Time.now.to_i, opts={})
        if @enable_bitcoinconsensus
          return bitcoinconsensus_verify_script(in_idx, outpoint_tx_or_script, block_timestamp, opts)
        end

        outpoint_idx  = @in[in_idx].prev_out_index
        script_sig    = @in[in_idx].script_sig
        
        # If given an entire previous transaction, take the script from it
        script_pubkey = if outpoint_tx_or_script.respond_to?(:out) 
          outpoint_tx_or_script.out[outpoint_idx].pk_script
        else
          # Otherwise, it's already a script.
          outpoint_tx_or_script
        end

        @scripts[in_idx] = Bitcoin::Script.new(script_sig, script_pubkey)
        return false if opts[:verify_sigpushonly] && !@scripts[in_idx].is_push_only?(script_sig)
        return false if opts[:verify_minimaldata] && !@scripts[in_idx].pushes_are_canonical?
        sig_valid = @scripts[in_idx].run(block_timestamp, opts) do |pubkey,sig,hash_type,subscript|
          hash = signature_hash_for_input(in_idx, subscript, hash_type)
          Bitcoin.verify_signature( hash, sig, pubkey.unpack("H*")[0] )
        end
        # BIP62 rule #6
        return false if opts[:verify_cleanstack] && !@scripts[in_idx].stack.empty?

        return sig_valid
      end

      # verify witness input signature +in_idx+ against the corresponding
      # output in +outpoint_tx+
      # outpoint
      #
      # options are: verify_sigpushonly, verify_minimaldata, verify_cleanstack, verify_dersig, verify_low_s, verify_strictenc
      def verify_witness_input_signature(in_idx, outpoint_tx_or_script, prev_out_amount, block_timestamp=Time.now.to_i, opts={})
        if @enable_bitcoinconsensus
          return bitcoinconsensus_verify_script(in_idx, outpoint_tx_or_script, block_timestamp, opts)
        end

        outpoint_idx  = @in[in_idx].prev_out_index
        script_sig    = ''

        # If given an entire previous transaction, take the script from it
        script_pubkey = if outpoint_tx_or_script.respond_to?(:out)
          Bitcoin::Script.new(outpoint_tx_or_script.out[outpoint_idx].pk_script)
        else
          # Otherwise, it's already a script.
          Bitcoin::Script.new(outpoint_tx_or_script)
        end

        if script_pubkey.is_p2sh?
          redeem_script = Bitcoin::Script.new(@in[in_idx].script_sig).get_pubkey
          script_pubkey = Bitcoin::Script.new(redeem_script.htb) if Bitcoin.hash160(redeem_script) == script_pubkey.get_hash160 # P2SH-P2WPKH or P2SH-P2WSH
        end

        @in[in_idx].script_witness.stack.each{|s|script_sig << Bitcoin::Script.pack_pushdata(s)}
        code_separator_index = 0

        if script_pubkey.is_witness_v0_keyhash? # P2WPKH
          @scripts[in_idx] = Bitcoin::Script.new(script_sig, Bitcoin::Script.to_hash160_script(script_pubkey.get_hash160))
        elsif script_pubkey.is_witness_v0_scripthash? # P2WSH
          witness_hex = @in[in_idx].script_witness.stack.last.bth
          witness_script = Bitcoin::Script.new(witness_hex.htb)
          return false unless Bitcoin.sha256(witness_hex) == script_pubkey.get_hash160
          @scripts[in_idx] = Bitcoin::Script.new(script_sig, Bitcoin::Script.to_p2sh_script(Bitcoin.hash160(witness_hex)))
        else
          return false
        end

        return false if opts[:verify_sigpushonly] && !@scripts[in_idx].is_push_only?(script_sig)
        return false if opts[:verify_minimaldata] && !@scripts[in_idx].pushes_are_canonical?
        sig_valid = @scripts[in_idx].run(block_timestamp, opts) do |pubkey,sig,hash_type,subscript|
          if script_pubkey.is_witness_v0_keyhash?
            hash = signature_hash_for_witness_input(in_idx, script_pubkey.to_payload, prev_out_amount, nil, hash_type)
          elsif script_pubkey.is_witness_v0_scripthash?
            hash = signature_hash_for_witness_input(in_idx, script_pubkey.to_payload, prev_out_amount, witness_hex.htb, hash_type, code_separator_index)
            code_separator_index += 1 if witness_script.codeseparator_count > code_separator_index
          end
          Bitcoin.verify_signature( hash, sig, pubkey.unpack("H*")[0] )
        end
        # BIP62 rule #6
        return false if opts[:verify_cleanstack] && !@scripts[in_idx].stack.empty?

        return sig_valid
      end

      def bitcoinconsensus_verify_script(in_idx, outpoint_tx_or_script, block_timestamp=Time.now.to_i, opts={})
        raise "Bitcoin::BitcoinConsensus shared library not found" unless Bitcoin::BitcoinConsensus.lib_available?

        # If given an entire previous transaction, take the script from it
        script_pubkey = if outpoint_tx_or_script.respond_to?(:out)
          outpoint_idx  = @in[in_idx].prev_out_index
          outpoint_tx_or_script.out[outpoint_idx].pk_script
        else
          # Otherwise, it's already a script.
          outpoint_tx_or_script
        end

        flags  = Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_NONE
        flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_P2SH        if block_timestamp >= 1333238400
        flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_SIGPUSHONLY if opts[:verify_sigpushonly]
        flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_MINIMALDATA if opts[:verify_minimaldata]
        flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_CLEANSTACK  if opts[:verify_cleanstack]
        flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_LOW_S       if opts[:verify_low_s]

        payload ||= to_payload
        Bitcoin::BitcoinConsensus.verify_script(in_idx, script_pubkey, payload, flags)
      end

      # convert to ruby hash (see also #from_hash)
      def to_hash(options = {})
        @hash ||= hash_from_payload(to_old_payload)
        h = {
          'hash' => @hash, 'ver' => @ver, # 'nid' => normalized_hash,
          'vin_sz' => @in.size, 'vout_sz' => @out.size,
          'lock_time' => @lock_time, 'size' => (@payload ||= to_payload).bytesize,
          'in'  =>  @in.map{|i|i.to_hash(options)},
          'out' => @out.map{|o| o.to_hash(options) }
        }
        h['nid'] = normalized_hash  if options[:with_nid]
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
      def self.from_hash(h, do_raise=true)
        tx = new(nil)
        tx.ver, tx.lock_time = (h['ver'] || h['version']), h['lock_time']
        ins  = h['in']  || h['inputs']
        outs = h['out'] || h['outputs']
        ins .each{|input|
          tx.add_in(TxIn.from_hash(input))
        }
        outs.each{|output|  tx.add_out TxOut.from_hash(output) }
        tx.instance_eval{ @hash = hash_from_payload(@payload = to_old_payload) }
        if h['hash'] && (h['hash'] != tx.hash)
          raise "Tx hash mismatch! Claimed: #{h['hash']}, Actual: #{tx.hash}" if do_raise
        end
        tx
      end

      # convert ruby hash to raw binary
      def self.binary_from_hash(h)
        tx = from_hash(h)
        tx.to_payload
      end

      # parse json representation
      def self.from_json(json_string); from_hash( JSON.load(json_string) ); end

      # convert json representation to raw binary
      def self.binary_from_json(json_string); from_json(json_string).to_payload; end

      # read binary block from a file
      def self.from_file(path); new( Bitcoin::Protocol.read_binary_file(path) ); end

      # read json block from a file
      def self.from_json_file(path); from_json( Bitcoin::Protocol.read_binary_file(path) ); end

      def size
        payload.bytesize
      end
      
      # Checks if transaction is final taking into account height and time 
      # of a block in which it is located (or about to be included if it's unconfirmed tx).
      def is_final?(block_height, block_time)
        # No time lock - tx is final.
        return true if lock_time == 0

        # Time based nLockTime implemented in 0.1.6
        # If lock_time is below the magic threshold treat it as a block height.
        # If lock_time is above the threshold, it's a unix timestamp.
        return true if lock_time < (lock_time < Bitcoin::LOCKTIME_THRESHOLD ? block_height : block_time)

        inputs.each{|input| return false if !input.is_final? }

        return true
      end
      
      def legacy_sigops_count
        # Note: input scripts normally never have any opcodes since every input script 
        # can be statically reduced to a pushdata-only script.
        # However, anyone is allowed to create a non-standard transaction with any opcodes in the inputs.
        count = 0
        self.in.each do |txin|
          count += Bitcoin::Script.new(txin.script_sig).sigops_count_accurate(false)
        end
        self.out.each do |txout|
          count += Bitcoin::Script.new(txout.pk_script).sigops_count_accurate(false)
        end
        count
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
          min_fee = 0 if tx_size < (mode == :block ? Bitcoin.network[:free_tx_bytes] : DEFAULT_BLOCK_PRIORITY_SIZE - 1_000)
        end

        # This code can be removed after enough miners have upgraded to version 0.9.
        # Until then, be safe when sending and require a fee if any output is less than CENT
        if min_fee < base_fee && mode == :block
          outputs.each do |output|
            if output.value < Bitcoin.network[:dust]
              # If per dust fee, then we add min fee for each output less than dust.
              # Otherwise, we set to min fee if there is any output less than dust.
              if Bitcoin.network[:per_dust_fee]
                min_fee += base_fee
              else
                min_fee = base_fee
                break
              end
            end
          end
        end

        min_fee = Bitcoin::network[:max_money] unless min_fee.between?(0, Bitcoin::network[:max_money])
        min_fee
      end

      def is_coinbase?
        inputs.size == 1 and inputs.first.coinbase?
      end

      def normalized_hash
        signature_hash_for_input(-1, nil, SIGHASH_TYPE[:all]).reverse.hth
      end
      alias :nhash :normalized_hash

      # get witness hash
      def witness_hash
        hash_from_payload(to_witness_payload)
      end

      # sort transaction inputs and outputs under BIP 69
      # https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
      def lexicographical_sort!
        inputs.sort_by!{|i| [i.previous_output, i.prev_out_index]}
        outputs.sort_by!{|o| [o.amount, o.pk_script.bth]}
      end

    end
  end
end
