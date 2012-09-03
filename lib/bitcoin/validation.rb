module Bitcoin::Validation

  MAX_BLOCK_SIZE = 1024 * 1024
  MAX_MONEY = 21e14
  INT_MAX = 2**32

  class ValidationError < StandardError
  end

  module Block
    def validate
      validate_rule :hash
      validate_rule :tx_list
      validate_rule :bits
      validate_rule :timestamp
      validate_rule :coinbase
      validate_rule :coinbase_scriptsig
      validate_rule :mrkl_root
    end

    def validate_rule method, *args
      raise ValidationError, "#{method} failed"  unless send("validate_#{method}", *args)
    end

    def validate_hash
      hash == recalc_block_hash
    end

    def validate_tx_list
      tx.any?
    end

    def validate_bits
      hash.to_i(16) <= Bitcoin.decode_compact_bits(bits).to_i(16)
    end

    def validate_timestamp
      Time.at(time) < Time.now + 2*60*60
    end

    def validate_coinbase
      coinbases = tx.map{|t| t.inputs.size == 1 && t.inputs.first.coinbase? }
      coinbases[0] == true && coinbases[1..-1].none?
    end

    def validate_coinbase_scriptsig
      (2..100).include?(tx.first.in.first.script_sig.bytesize)
    end

    def validate_mrkl_root
      mrkl_root.reverse.unpack("H*")[0] == Bitcoin.hash_mrkl_tree(tx.map(&:hash))[-1]
    end
  end

  module Tx
    def validate(prev_txs)
      validate_rule :hash
      validate_rule :lists
      validate_rule :max_size
      validate_rule :output_values
      validate_rule :inputs
      validate_rule :lock_time
      validate_rule :min_size
      validate_rule :standard
      validate_rule :prev_out, prev_txs
      validate_rule :signatures, prev_txs
      validate_rule :spent, prev_txs
      validate_rule :input_values, prev_txs
      validate_rule :output_sum, prev_txs
    end

    def validate_rule method, *args
      raise ValidationError, "#{method} failed"  unless send("validate_#{method}", *args)
    end

    def validate_hash
      hash == generate_hash(to_payload)
    end

    def validate_lists
      self.in.any? && self.out.any?
    end

    def validate_max_size
      to_payload.bytesize <= MAX_BLOCK_SIZE
    end

    def validate_output_values
      out.map(&:value).inject(:+) <= MAX_MONEY
    end

    def validate_inputs
      inputs.map(&:coinbase?).none?
    end

    def validate_lock_time
      lock_time <= INT_MAX
    end

    def validate_min_size
      to_payload.bytesize >= 100
    end

    def validate_standard
      out.map {|o| Bitcoin::Script.new(o.pk_script).is_standard? }.all?
    end

    def validate_prev_out prev_txs
      @in.map.with_index {|txin, idx| !!prev_txs[idx].out[txin.prev_out_index] }.all?
    end

    # TODO: validate coinbase maturity

    def validate_signatures prev_txs
      @in.map.with_index {|txin, idx| verify_input_signature(idx, prev_txs[idx]) }.all?
    end

    def validate_spent prev_txs
      @in.map.with_index {|txin, idx| !!prev_txs[idx].out[txin.prev_out_index].get_next_in }.none?
    end

    def validate_input_values prev_txs
      @in.map.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index].value }
        .inject(:+) < MAX_MONEY
    end

    def validate_output_sum prev_txs
      @in.map.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index].value }
        .inject(:+) >= @out.map(&:value).inject(:+)
    end
  end
end
