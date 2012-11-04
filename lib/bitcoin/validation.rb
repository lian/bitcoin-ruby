module Bitcoin::Validation

  # maximum size of a block (in bytes)
  MAX_BLOCK_SIZE = 1_000_000

  # maximum number of signature operations in a block
  MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50

  # the number of base units ("satoshis") that make up one bitcoin
  COIN = 100_000_000

  # total number of base units in existence
  MAX_MONEY = 21_000_000 * COIN

  # maximum integer value
  INT_MAX = 0xffffffff

  # number of confirmations required before coinbase tx can be spent
  COINBASE_MATURITY = 100

  # interval (in blocks) for difficulty retarget
  RETARGET = 2016

  # interval (in blocks) for mining reward reduction
  REWARD_DROP = 210_000

  class ValidationError < StandardError
  end


  class Block
    attr_accessor :block, :store, :prev_block

    RULES = {
      syntax: [:hash, :tx_list, :bits, :max_timestamp, :coinbase, :coinbase_scriptsig, :mrkl_root, :transactions_syntax],
      context: [:prev_hash, :difficulty, :coinbase_value, :min_timestamp, :transactions_context]
    }

    # validate block rules. +opts+ are:
    # rules:: which rulesets to validate (default: [:syntax, :context])
    # raise_errors:: whether to raise ValidationError on failure (default: false)
    def validate(opts = {})
      return true  if KNOWN_EXCEPTIONS.include?(block.hash)
      opts[:rules] ||= [:syntax, :context]

      opts[:rules].each do |name|
        store.log.info { "validating block #{name} #{block.hash} (#{block.to_payload.bytesize} bytes)" }
        RULES[name].each.with_index do |rule, i|
          unless send(rule)
            raise ValidationError, "block error: #{name} check #{i} - #{rule} failed"  if opts[:raise_errors]
            return false
          end
        end
      end
      true
    end

    # setup new validator for given +block+, validating context with +store+,
    # optionally passing the +prev_block+ for optimization.
    def initialize block, store, prev_block = nil
      @block, @store = block, store
      @prev_block = prev_block || store.get_block(block.prev_block.reverse_hth)
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
      block.mrkl_root.reverse_hth == Bitcoin.hash_mrkl_tree(block.tx.map(&:hash))[-1]
    end

    def prev_hash
      @prev_block && @prev_block.hash == block.prev_block.reverse_hth
    end

    # check that bits satisfy required difficulty
    def difficulty
      next_bits_required == block.bits
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

    def next_bits_required
      index = (prev_block.depth + 1) / 2016
      max_target = Bitcoin.decode_compact_bits(Bitcoin.network[:proof_of_work_limit]).to_i(16)

      return Bitcoin.network[:proof_of_work_limit]  if index == 0
      first = store.db[:blk][depth: (index-1)*2016, chain: 0]
      last = store.db[:blk][depth: index*2016-1, chain: 0]

      nActualTimespan = last[:time] - first[:time]
      nTargetTimespan = 14*24*60*60
      nActualTimespan = [nActualTimespan, nTargetTimespan/4].max
      nActualTimespan = [nActualTimespan, nTargetTimespan*4].min

      target = Bitcoin.decode_compact_bits(last[:bits]).to_i(16)
      new_target = [max_target, (target * nActualTimespan)/nTargetTimespan].min
      Bitcoin.encode_compact_bits new_target.to_s(16)
    rescue
      p $!
      binding.pry
    end

    KNOWN_EXCEPTIONS = [
      Bitcoin.network[:genesis_hash], # genesis block
      "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec", # BIP30 exception
      "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721", # BIP30 exception
    ]

  end

  class Tx
    attr_accessor :tx, :store

    RULES = {
      syntax: [:hash, :lists, :max_size, :output_values, :inputs, :lock_time, :min_size, :standard],
      context: [:prev_out, :signatures, :spent, :input_values, :output_sum]
    }

    # validate tx rules. +opts+ are:
    # rules:: which rulesets to validate (default: [:syntax, :context])
    # raise_errors:: whether to raise ValidationError on failure (default: false)
    def validate(opts = {})
      return true  if KNOWN_EXCEPTIONS.include?(tx.hash)
      opts[:rules] ||= [:syntax, :context]
      opts[:rules].each do |name|
        store.log.debug { "validating tx #{name} #{tx.hash} (#{tx.to_payload.bytesize} bytes)" }
        RULES[name].each.with_index do |rule, i|
          unless send(rule)
            raise ValidationError, "tx error: #{name} check #{i} - #{rule} failed"  if opts[:raise_errors]
            return false
          end
        end
      end
      true
    end

    KNOWN_EXCEPTIONS = [
      # p2sh with invalid inner script, accepted by old miner before 4-2012 switchover
      "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192",
      # p2sh with invalid inner script, accepted by old miner before 4-2012 switchover (testnet)
      "b3c19d78b4953b694717a47d9852f8ea1ccd4cf93a45ba2e43a0f97d7cdb2655"
    ]

    # setup new validator for given +tx+, validating context with +store+.
    # also needs the +block+ to find prev_outs for chains of tx inside one block.
    def initialize tx, store, block = nil
      @tx, @store, @block = tx, store, block
    end

    # check that tx hash matches data
    def hash
      tx.hash == tx.generate_hash(tx.to_payload)
    end

    # check that tx has at least one input and one output
    def lists
      tx.in.any? && tx.out.any?
    end

    # check that tx size doesn't exceed MAX_BLOCK_SIZE.
    def max_size
      tx.to_payload.bytesize <= MAX_BLOCK_SIZE
    end

    # check that total output value doesn't exceed MAX_MONEY.
    def output_values
      tx.out.inject(0) {|e, out| e + out.value } <= MAX_MONEY
    end

    # check that none of the inputs is coinbase
    # (coinbase tx do not get validated)
    def inputs
      tx.inputs.none?(&:coinbase?)
    end

    # check that lock_time doesn't exceed INT_MAX
    def lock_time
      tx.lock_time <= INT_MAX
    end

    # check that min_size is at least 86 bytes
    # (smaller tx can't be valid / do anything useful)
    def min_size
      tx.to_payload.bytesize >= 86
    end

    # check that tx matches "standard" rules.
    # this is currently disabled since not all miners enforce it.
    def standard
      return true  # not enforced by all miners
      tx.out.all? {|o| Bitcoin::Script.new(o.pk_script).is_standard? }
    end

    # check that all prev_outs exist
    # (and are in a block in the main chain, or the current block; see #prev_txs)
    def prev_out
      missing = tx.in.reject.with_index {|txin, idx|
        prev_txs[idx].out[txin.prev_out_index] rescue false }
      return true  if prev_txs.size == tx.in.size && missing.empty?
      missing.each {|i| store.log.warn { "prev out #{i.prev_out.reverse_hth}:#{i.prev_out_index}" } }
      false
    end

    # TODO: validate coinbase maturity

    # check that all input signatures are valid
    def signatures
      tx.in.map.with_index {|txin, idx| tx.verify_input_signature(idx, prev_txs[idx]) }.all?
    end

    # check that none of the prev_outs are already spent in the main chain
    def spent
      tx.in.map.with_index {|txin, idx|
        next false  if @block && @block.tx.include?(prev_txs[idx])
        next false  unless next_in = prev_txs[idx].out[txin.prev_out_index].get_next_in
        next false  unless next_tx = next_in.get_tx
        next false  unless next_block = next_tx.get_block
        next_block.chain == Bitcoin::Storage::Backends::StoreBase::MAIN
      }.none?
    end

    # check that the total input value doesn't exceed MAX_MONEY
    def input_values
      tx.in.map.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index].value }
        .inject(:+) < MAX_MONEY
    end

    # check that the total output value doesn't exceed the total input value
    def output_sum
      tx.in.map.with_index {|txin, idx| prev_txs[idx].out[txin.prev_out_index].value }
        .inject(:+) >= tx.out.map(&:value).inject(:+)
    end

    # collect prev_txs needed to verify the inputs of this tx.
    # only returns tx that are in a block in the main chain or the current block.
    def prev_txs
      @prev_txs ||= tx.in.map {|i|
        prev_tx = store.get_tx(i.prev_out.reverse_hth)
        next nil  if !prev_tx && !@block

        if store.db && store.db.is_a?(Sequel::Database)
          block = store.db[:blk][id: prev_tx.blk_id]  if prev_tx
          next prev_tx  if block && block[:chain] == 0
        else
          next prev_tx  if prev_tx.get_block && prev_tx.get_block.chain == 0
        end
        next  nil if !@block
        @block.tx.find {|t| t.binary_hash == i.prev_out }
      }.compact
    end

  end
end
