require_relative '../spec_helper'

include Bitcoin::Builder
include Bitcoin::Storage
include Bitcoin::Validation

describe "block rules" do

  def balance addr
    @store.get_balance(Bitcoin.hash160_from_address(addr))
  end

  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.sequel(:db => "sqlite:/")
    @store.log.level = :warn
    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("f"*64)
    @key = Bitcoin::Key.generate
    @block0 = create_block "00"*32, false, [], @key
    Bitcoin.network[:genesis_hash] = @block0.hash
    @store.store_block(@block0)
    @store.get_head.should == @block0
    @block1 = create_block @block0.hash, true, [], @key
    @store.get_head.should == @block1
    @block = create_block @block1.hash, false
  end

  def check_block blk, msg
    b = blk.dup
    if block_given?
      yield(b); b.bits = Bitcoin.network[:proof_of_work_limit]; b.recalc_block_hash
    end
    -> { b.validator(@store).validate(raise_errors: true) }.should
      .raise(ValidationError).message.should =~ msg
  end

  it "1. Check syntactic correctness" do
    block = create_block @block1.hash, false
    block.hash = "\x00" * 32
    block.bits = Bitcoin.network[:proof_of_work_limit]
    -> { block.validator(@store).validate(raise_errors: true) }
      .should.raise(ValidationError).message.should =~ /hash/
  end

  it "3. Transaction list must be non-empty" do
    check_block(@block, /tx_list/) {|b| b.tx = [] }
  end

  it "4. Block hash must satisfy claimed nBits proof of work" do
    @block.bits = Bitcoin.encode_compact_bits("0000#{"ff" * 30}")
    @block.recalc_block_hash
    check_block(@block, /bits/)
  end

  it "5. Block timestamp must not be more than two hours in the future" do
    check_block(@block, /timestamp/) {|b| b.time = (Time.now + 3 * 60 * 60).to_i }
  end

  it "6. First transaction must be coinbase (i.e. only 1 input, with hash=0, n=-1), the rest must not be" do
    block = create_block @block1.hash, false, [
      ->(tx) { create_tx(tx, @block1.tx.first, 0, [[50, @key]]) } ], @key
    check_block(block, /coinbase/) {|b| b.tx = b.tx.reverse }
    check_block(block, /coinbase/) {|b| b.tx << b.tx[0] }
  end

  it "8. For the coinbase (first) transaction, scriptSig length must be 2-100" do
    check_block(@block, /coinbase_scriptsig/) {|b| b.tx[0].in[0].script_sig = "\x01" }
    check_block(@block, /coinbase_scriptsig/) {|b| b.tx[0].in[0].script_sig = "\x01" * 101 }
  end

  it "10. Verify Merkle hash" do
    check_block(@block, /mrkl_root/) {|b| b.mrkl_root = "\x00" * 32 }
  end

  it "12. Check that nBits value matches the difficulty rules" do
    block = create_block @block1.hash, false, [], @key
    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("0000#{"ff"*30}")
    -> { block.validator(@store).validate(raise_errors: true) }
      .should.raise(ValidationError).message.should =~ /difficulty/
  end

  it "should allow chains of unconfirmed transactions" do
    tx1 = tx {|t| create_tx(t, @block1.tx.first, 0, [[50, @key]]) }
    tx2 = tx {|t| create_tx(t, tx1, 0, [[50, @key]]) }
    block = create_block(@block1.hash, false, [], @key)
    block.tx << tx1; block.tx << tx2
    block.bits = Bitcoin.encode_compact_bits("f"*64)
    block.mrkl_root = [Bitcoin.hash_mrkl_tree(block.tx.map(&:hash)).last].pack("H*").reverse
    block.recalc_block_hash
    @store.store_block(block).should == [2, 0]
  end

  it "should check coinbase output value" do
    block2 = create_block(@block1.hash, false, [
        ->(tx) { create_tx(tx, @block1.tx.first, 0, [[40e8, @key]])}
      ], @key, 60e8)
    @store.store_block(block2).should == [2, 0]

    block3 = create_block(block2.hash, false, [], @key, 60e8)
    -> { @store.store_block(block3) }.should.raise(ValidationError)

    Bitcoin::Validation::REWARD_DROP = 2
    block4 = create_block(block2.hash, false, [], @key, 50e8)
    -> { @store.store_block(block4) }.should.raise(ValidationError)

    block5 = create_block(block2.hash, false, [], @key, 25e8)
    @store.store_block(block5).should == [3, 0]
    Bitcoin::Validation::REWARD_DROP = 210_000
  end

end

describe "tx rules" do
  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.sequel(:db => "sqlite:/")
    @store.log.level = :warn

    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("f"*64)
    @key = Bitcoin::Key.generate
    @block0 = create_block "00"*32, false, [], @key
    Bitcoin.network[:genesis_hash] = @block0.hash
    @store.store_block(@block0)
    @store.get_head.should == @block0
    @block1 = create_block @block0.hash, true, [], @key
    @store.get_head.should == @block1
    @tx = tx {|t| create_tx(t, @block1.tx.first, 0, [[50, @key]]) }
  end

  def check_tx tx, msg
    t = tx.dup
    yield(t) && t.instance_eval { @hash = generate_hash(to_payload) }  if block_given?
    -> { t.validator(@store).validate(raise_errors: true) }.should.raise(ValidationError).message.should =~ msg
  end

  it "should validate" do
    validator = @tx.validator(@store)
    validator.validate.should == true
    validator.validate(raise_errors: true).should == true
    @tx.instance_eval { @hash = "f"*64 }
    validator = @tx.validator(@store)
    validator.validate.should == false
    -> { validator.validate(raise_errors: true) }.should.raise(ValidationError)
  end

  it "1. Check syntactic correctness" do
    @tx.instance_eval { @hash = "f"*64 }
    -> { @tx.validator(@store).validate(raise_errors: true) }
      .should.raise(ValidationError).message.should =~ /hash/
  end

  it "2. Make sure neither in or out lists are empty" do
    check_tx(@tx, /lists/) {|tx| tx.instance_eval { @in = [] } }
    check_tx(@tx, /lists/) {|tx| tx.instance_eval { @out = [] } }
  end

  it "3. Size in bytes < MAX_BLOCK_SIZE" do
    s = MAX_BLOCK_SIZE; Bitcoin::Validation::MAX_BLOCK_SIZE = 1000
    check_tx(@tx, /size/) {|tx| tx.out[0].pk_script = "f" * 1001 }
    Bitcoin::Validation::MAX_BLOCK_SIZE = s
  end

  it "4. Each output value, as well as the total, must be in legal money range" do
    check_tx(@tx, /output_values/) {|tx| tx.out[0].value = MAX_MONEY + 1 }
  end

  it "5. Make sure none of the inputs have hash=0, n=-1" do
    check_tx(@tx, /inputs/) do |tx|
      tx.in.first.prev_out = "\x00"*32
      tx.in.first.prev_out_index = 4294967295
    end
  end

  it "6. Check that nLockTime <= INT_MAX, size in bytes >= 100, and sig opcount <= 2" do
    check_tx(@tx, /lock_time/) {|tx| tx.lock_time = INT_MAX + 1 }
    # check_tx(@tx, /size/) {|tx| tx.in[0].script_sig = ""; tx.out[0].pk_script = "" }
    # TODO: validate sig opcount
  end

  # it "7. Reject 'nonstandard' transactions: scriptSig doing anything other than pushing numbers on the stack, or scriptPubkey not matching the two usual forms" do
  #   check_tx(@tx, /standard/) {|tx| tx.out[0].pk_script = Bitcoin::Script.from_string("OP_ADD OP_DUP OP_DROP").raw }
  # end

  # it "9. Reject if any other tx in the pool uses the same transaction output as one used by this tx." do
  # end

  it "11. For each input, if we are using the nth output of the earlier transaction, but it has fewer than n+1 outputs, reject this transaction" do
    check_tx(@tx, /prev_out/) {|tx| tx.in[0].prev_out_index = 2 }
  end

  it "13. Verify crypto signatures for each input; reject if any are bad" do
    check_tx(@tx, /signature/) {|tx| @tx.in[0].script_sig[-1] = "\x00" }
  end

  it "14. For each input, if the referenced output has already been spent by a transaction in the main branch, reject this transaction" do
    block2 = create_block(@block1.hash, true, [
        ->(tx) {create_tx(tx, @block1.tx.first, 0, [[50, @key]])}], @key)
    check_tx(@tx, /spent/)
  end

  it "15. Using the referenced output transactions to get input values, check that each input value, as well as the sum, are in legal money range" do
    @store.db[:txout].where(id: 2).update(value: 22e14)
    check_tx(@tx, /input_values/)
  end

  it "16. Reject if the sum of input values < sum of output values" do
    tx = tx {|t| create_tx(t, @block1.tx.first, 0, [[100e8, @key]]) }
    check_tx(tx, /output_sum/)
  end

end
