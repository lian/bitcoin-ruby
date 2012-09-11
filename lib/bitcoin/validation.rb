module Bitcoin::Validation

  MAX_BLOCK_SIZE = 1_000_000
  MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50
  COIN = 100_000_000
  MAX_MONEY = 21_000_000 * COIN
  INT_MAX = 0xffffffff
  COINBASE_MATURITY = 100
  RETARGET = 2016
  REWARD_DROP = 210_000

  class ValidationError < StandardError
  end


  class Block
    attr_accessor :block, :store, :prev_block

    RULES = {
      syntax: [:hash, :tx_list, :bits, :max_timestamp, :coinbase, :coinbase_scriptsig, :mrkl_root, :transactions_syntax],
      context: [:prev_hash, :difficulty, :coinbase_value, :min_timestamp, :transactions_context]
    }

    # validate all rules. if +error+ is true, raise errors when rules fail
    def validate(opts = {})
      return true if block.hash == Bitcoin.network[:genesis_hash]
      opts[:rules] ||= [:syntax, :context]

      opts[:rules].each do |name|
        store.log.info { "validating block #{name} #{block.hash} (#{block.to_payload.bytesize} bytes)" }
        RULES[name].each.with_index do |rule, i|
          unless send(rule)
            raise ValidationError, "block error: context check #{i} - #{rule} failed"  if opts[:raise_errors]
            return false
          end
        end
      end
      true
    end

    def initialize block, store, prev_block = nil
      @block, @store = block, store
      @prev_block = prev_block || store.get_block(block.prev_block.reverse.unpack("H*")[0])
    end

    # check that block hash matches header
    def hash
      block.hash == block.recalc_block_hash
    end

    # check that block has at least one tx (the coinbase)
    def tx_list
      block.tx.any?
    end

    # check that block hash matches claimed bits
    def bits
      block.hash.to_i(16) <= Bitcoin.decode_compact_bits(block.bits).to_i(16)
    end

    # check that block time is not greater than max
    def max_timestamp
      Time.at(block.time) < Time.now + 2*60*60
    end

    # check that coinbase is present
    def coinbase
      coinbase, *rest = block.tx.map{|t| t.inputs.size == 1 && t.inputs.first.coinbase? }
      coinbase && rest.none?
    end

    # check that coinbase scriptsig is valid
    def coinbase_scriptsig
      block.tx.first.in.first.script_sig.bytesize.between?(2,100)
    end

    # check that coinbase value is valid; no more than reward + fees
    def coinbase_value
      reward = ((50.0 / (2 ** (store.get_depth / REWARD_DROP.to_f).floor)) * 1e8).to_i
      fees = block.tx[1..-1].map.with_index do |t, idx|
        val = tx_validators[idx]
        t.in.map.with_index {|i, idx|
          val.prev_txs[idx].out[i.prev_out_index].value rescue 0
        }.inject(:+)
      end.inject(:+) || 0
      coinbase_output = block.tx[0].out.map(&:value).inject(:+)
      coinbase_output <= reward + fees
    end

    # check that merkle root matches transaction hashes
    def mrkl_root
      block.mrkl_root.reverse.unpack("H*")[0] == Bitcoin.hash_mrkl_tree(block.tx.map(&:hash))[-1]
    end

    def prev_hash
      @prev_block && @prev_block.hash == block.prev_block.reverse.unpack("H*")[0]
    end

    # check that bits satisfy required difficulty
    def difficulty
      true # next_bits_required == block.bits
    end

    # check that timestamp is not too old
    def min_timestamp
      true # TODO
    end

    # check transactions
    def transactions_syntax
      tx_validators.all?{|v|
        begin
          v.validate(rules: [:syntax], raise_errors: true)
        rescue ValidationError
          store.log.info { $!.message }
          return false
        end
      }
    end

    def transactions_context
      tx_validators.all?{|v|
        begin
          v.validate(rules: [:context], raise_errors: true)
        rescue ValidationError
          store.log.info { $!.message }
          return false
        end
      }
    end

    private

    def tx_validators
      @tx_validators ||= block.tx[1..-1].map {|tx| tx.validator(store, block) }
    end

    # def next_bits_required
    #   limit = Bitcoin.network[:proof_of_work_limit]
    #   return limit  if prev_block.hash == Bitcoin.network[:genesis_hash]
    #   return block.bits  if (prev_block.depth + 1) % RETARGET != 0

    #   target = 2 * 60 * 60 * 24
    #   min = target / 4
    #   max = target * 4
    #   diff = prev_block.time - store.get_block_by_depth(prev_block.depth - RETARGET + 1).time
    #   diff = min  if diff < min
    #   diff = max  if diff > max

    #   retarget = Bitcoin.decode_compact_bits(prev_block.bits).to_i(16) * diff / target

    #   if retarget > Bitcoin.decode_compact_bits(limit).to_i(16)
    #     limit
    #   else
    #     Bitcoin.encode_compact_bits(retarget.to_s(16))
    #   end
    # end

  end

  class Tx
    attr_accessor :tx, :store

    RULES = {
      syntax: [:hash, :lists, :max_size, :output_values, :inputs, :lock_time, :min_size, :standard],
      context: [:prev_out, :signatures, :spent, :input_values, :output_sum]
    }

    # validate all rules. if +error+ is true, raise errors when rules fail
    def validate(opts = {})
      opts[:rules] ||= [:syntax, :context]

      opts[:rules].each do |name|
        store.log.info { "validating tx #{name} #{tx.hash} (#{tx.to_payload.bytesize} bytes)" }
        RULES[name].each.with_index do |rule, i|
          unless send(rule)
            raise ValidationError, "#tx error: context check #{i} - #{rule} failed"  if opts[:raise_errors]
            return false
          end
        end
      end
      true
    end

    KNOWN_EXCEPTIONS = [
      # p2sh with invalid inner script, accepted by old miner before 4-2012 switchover
      "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192"
    ]

    def initialize tx, store, block = nil
      @tx, @store, @block = tx, store, block
    end

    def matches_known_exception
      KNOWN_EXCEPTIONS.include?(@tx.hash)
    end

    def hash
      tx.hash == tx.generate_hash(tx.to_payload)
    end

    def lists
      tx.in.any? && tx.out.any?
    end

    def max_size
      tx.to_payload.bytesize <= MAX_BLOCK_SIZE
    end

    def output_values
      tx.out.inject(0) {|e, out| e + out.value } <= MAX_MONEY
    end

    def inputs
      tx.inputs.none?(&:coinbase?)
    end

    def lock_time
      tx.lock_time <= INT_MAX
    end

    def min_size
      tx.to_payload.bytesize >= 86
    end

    def standard
      return true  # not enforced by all miners
      tx.out.all? {|o| Bitcoin::Script.new(o.pk_script).is_standard? }
    end

    def prev_out
      return false  unless prev_txs.size == tx.in.size
      tx.in.reject.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index] rescue false }.empty?
    end

    # TODO: validate coinbase maturity

    def signatures
      tx.in.map.with_index {|txin, idx| tx.verify_input_signature(idx, prev_txs[idx]) }.all?
    end

    def spent
      tx.in.map.with_index {|txin, idx|
        next false  if @block && @block.tx.include?(prev_txs[idx])
        next false  unless next_in = prev_txs[idx].out[txin.prev_out_index].get_next_in
        next false  unless next_tx = next_in.get_tx
        next false  unless next_block = next_tx.get_block
        next_block.chain == Bitcoin::Storage::Backends::StoreBase::MAIN
      }.none?
    end

    def input_values
      tx.in.map.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index].value }
        .inject(:+) < MAX_MONEY
    end

    def output_sum
      tx.in.map.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index].value }
        .inject(:+) >= tx.out.map(&:value).inject(:+)
    end


    def prev_txs
      @prev_txs ||= tx.in.map {|i|
        prev_tx = store.get_tx(i.prev_out.reverse.unpack("H*")[0])
        next nil  if !prev_tx && !@block

        if store.db && store.db.is_a?(Sequel::Database)
          block = store.db[:blk][id: prev_tx.blk_id]  if prev_tx
          next prev_tx  if block && block[:chain] == 0
        else
          next prev_tx  if prev_tx.get_block && prev_tx.get_block.chain == 0
        end
        @block.tx.find {|t| t.binary_hash == i.prev_out }
      }.compact
    end

  end
end
