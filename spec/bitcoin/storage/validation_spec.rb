require_relative '../spec_helper'

include Bitcoin::Builder
include Bitcoin::Storage

describe "block rules" do

  def balance addr
    @store.get_balance(Bitcoin.hash160_from_address(addr))
  end

  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.sequel(:db => "sqlite:/")
    @store.log.level = :warn
    @block0 = Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin'))
    @store.store_block(@block0)
    @key = Bitcoin::Key.generate
    @block1 = create_block @block0.hash, true, [], @key
    @block = create_block @block1.hash, false
  end

  def check_block blk, msg
    b = blk.dup
    if block_given?
      yield(b); b.bits = Bitcoin.encode_compact_bits("f"*64); b.recalc_block_hash
    end
    -> { @store.store_block b }.should.raise(Bitcoin::Validation::ValidationError)
      .message.should =~ msg
  end

  it "1. Check syntactic correctness" do
    block = create_block @block1.hash, false
    block.hash = "\x00" * 32
    block.bits = Bitcoin.encode_compact_bits("f"*64)
    -> { @store.store_block block }
      .should.raise(Bitcoin::Validation::ValidationError).message.should =~ /hash/
  end

  it "3. Transaction list must be non-empty" do
    check_block(@block, /tx_list/) {|b| b.tx = []}
  end

  it "4. Block hash must satisfy claimed nBits proof of work" do
    @block.nonce = 123; @block.recalc_block_hash
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
end

describe "tx rules" do
  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.sequel(:db => "sqlite:/")
    @store.log.level = :warn
    @block0 = Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin'))
    @store.store_block(@block0)
    @key = Bitcoin::Key.generate
    @block1 = create_block @block0.hash, true, [], @key
    @tx = tx {|t| create_tx(t, @block1.tx.first, 0, [[50, @key]]) }
  end

  def check_tx tx, msg
    t = tx.dup
    yield(t) && t.instance_eval { @hash = generate_hash(to_payload) }  if block_given?
    -> { @store.store_tx t, true }.should.raise(Bitcoin::Validation::ValidationError)
      .message.should =~ msg
  end

  it "1. Check syntactic correctness" do
    @tx.instance_eval { @hash = "f"*64 }
    -> { @store.store_tx @tx, true }
      .should.raise(Bitcoin::Validation::ValidationError).message.should =~ /hash/
  end

  it "2. Make sure neither in or out lists are empty" do
    check_tx(@tx, /lists/) {|tx| tx.instance_eval { @in = [] } }
    check_tx(@tx, /lists/) {|tx| tx.instance_eval { @out = [] } }
  end

  it "3. Size in bytes < MAX_BLOCK_SIZE" do
    s = Bitcoin::Validation::MAX_BLOCK_SIZE; Bitcoin::Validation::MAX_BLOCK_SIZE = 1000
    check_tx(@tx, /size/) {|tx|
      tx.out[0].pk_script = "f" * (Bitcoin::Validation::MAX_BLOCK_SIZE + 1) }
    Bitcoin::Validation::MAX_BLOCK_SIZE = s
  end

  it "4. Each output value, as well as the total, must be in legal money range" do
    check_tx(@tx, /output_values/) {|tx| tx.out[0].value = Bitcoin::Validation::MAX_MONEY + 1 }
  end

  it "5. Make sure none of the inputs have hash=0, n=-1" do
    check_tx(@tx, /inputs/) do |tx|
      tx.in.first.prev_out = "\x00"*32
      tx.in.first.prev_out_index = 4294967295
    end
  end

  it "6. Check that nLockTime <= INT_MAX, size in bytes >= 100, and sig opcount <= 2" do
    check_tx(@tx, /lock_time/) {|tx| tx.lock_time = Bitcoin::Validation::INT_MAX + 1 }
    check_tx(@tx, /size/) {|tx| tx.in[0].script_sig = ""; tx.out[0].pk_script = "" }
    # TODO: validate sig opcount
  end

  it "7. Reject 'nonstandard' transactions: scriptSig doing anything other than pushing numbers on the stack, or scriptPubkey not matching the two usual forms" do
    check_tx(@tx, /standard/) {|tx| tx.out[0].pk_script = Bitcoin::Script.from_string("OP_ADD OP_DUP OP_DROP").raw }
  end

  it "9. Reject if any other tx in the pool uses the same transaction output as one used by this tx." do
    @store.store_tx @tx
    check_tx(@tx, /spent/)
  end

  # it "10. For each input, look in the main branch and the transaction pool to find the referenced output transaction. If the output transaction is missing for any input, this will be an orphan transaction. Add to the orphan transactions, if a matching transaction is not in there already." do

  # end

  it "11. For each input, if we are using the nth output of the earlier transaction, but it has fewer than n+1 outputs, reject this transaction" do
    check_tx(@tx, /prev_out/) {|tx| tx.in[0].prev_out_index = 2 }
  end

  it "13. Verify crypto signatures for each input; reject if any are bad" do
    check_tx(@tx, /signature/) {|tx| @tx.in[0].script_sig[-1] = "\x00" }
  end

  it "14. For each input, if the referenced output has already been spent by a transaction in the main branch, reject this transaction" do
    @store.store_tx @tx
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
