module Bitcoin::Validation

  MAX_BLOCK_SIZE = 1_000_000
  MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50
  COIN = 100_000_000
  MAX_MONEY = 21_000_000 * COIN
  INT_MAX = 0xffffffff
  COINBASE_MATURITY = 100

  class ValidationError < StandardError
  end

  class Block
    attr_accessor :block, :store

    RULES = [:hash, :tx_list, :bits, :timestamp, :coinbase, :coinbase_scriptsig, :mrkl_root]

    def initialize block, store
      @block, @store = block, store
    end

    def validate validate_tx = true
      run_validation(validate_tx) {|rule, i|
        raise ValidationError, "block error: rule #{i} - #{rule} failed" }
    end

    def valid? validate_tx = true
      run_validation(validate_tx) { return false }
    end

    def run_validation validate_tx
      store.log.info { "validating block #{block.hash} (#{block.to_payload.bytesize} bytes)" }
      RULES.each.with_index {|rule, i| yield(rule, i)  unless send(rule) }
      yield(:transactions, RULES.size)  if validate_tx && !transactions.all?(&:valid?)
      true
    end

    def hash
      block.hash == block.recalc_block_hash
    end

    def tx_list
      block.tx.any?
    end

    def bits
      block.hash.to_i(16) <= Bitcoin.decode_compact_bits(block.bits).to_i(16)
    end

    def timestamp
      Time.at(block.time) < Time.now + 2*60*60
    end

    def coinbase
      coinbase, *rest = block.tx.map{|t| t.inputs.size == 1 && t.inputs.first.coinbase? }
      coinbase && rest.none?
    end

    def coinbase_scriptsig
      block.tx.first.in.first.script_sig.bytesize.between?(2,100)
    end

    def mrkl_root
      block.mrkl_root.reverse.unpack("H*")[0] == Bitcoin.hash_mrkl_tree(block.tx.map(&:hash))[-1]
    end

    def transactions
      block.tx[1..-1].map {|tx| tx.validator(store, block) }  if block.tx.any?
    end
  end

  class Tx
    attr_accessor :tx, :store

    RULES = [:hash, :lists, :max_size, :output_values, :inputs, :lock_time, :min_size, :standard,
      :prev_out, :signatures, :spent, :input_values, :output_sum]

    KNOWN_EXCEPTIONS = [
      # p2sh with invalid inner script, accepted by old miner before 4-2012 switchover
      "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192"
    ]

    def initialize tx, store, block = nil
      @tx, @store, @block = tx, store, block
    end

    def validate; run_validation {|rule, i| raise ValidationError, "tx error: rule #{i} - #{rule} failed" }; end

    def valid?; run_validation { return false }; end

    def run_validation
      return true  if matches_known_exception
      store.log.info { "validating tx #{@tx.hash} (#{tx.to_payload.bytesize} bytes)" }
      RULES.each {|rule, i| yield(rule, i)  unless send(rule) }
      true
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

    private

    def prev_txs
      @prev_txs ||= tx.in.map {|i|
        prev_tx = store.get_tx(i.prev_out.reverse.unpack("H*")[0])

        if store.db && store.db.is_a?(Sequel::Database)
          block = store.db[:blk][id: prev_tx.blk_id]  if prev_tx
          next nil  if prev_tx && (!block || block[:chain] != 0)
        else
          next nil  if prev_tx && (!prev_tx.get_block || prev_tx.get_block.chain != 0)
        end
        next nil  if !prev_tx && !@block
        prev_tx || @block.tx.find {|t| t.binary_hash == i.prev_out }
      }.compact
    end

  end
end
