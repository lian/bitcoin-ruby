# encoding: ascii-8bit

require_relative '../spec_helper'

include Bitcoin::Builder
include Bitcoin::Storage
include Bitcoin::Validation

Bitcoin.network = :spec

[
 [:sequel, :sqlite],
 [:utxo, :sqlite, index_all_addrs: true],
 [:sequel, :postgres],
 [:utxo, :postgres, index_all_addrs: true],
 [:sequel, :mysql],
 [:utxo, :mysql, index_all_addrs: true],
].compact.each do |options|

  next  unless storage = setup_db(*options)

  describe "block rules (#{options[0]} - #{options[1]})" do

  def balance addr
    @store.get_balance(Bitcoin.hash160_from_address(addr))
  end

  before do
    @store = storage
    @store.reset
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

  def check_block blk, error
    b = blk.dup
    if block_given?
      yield(b); b.bits = Bitcoin.network[:proof_of_work_limit]; b.recalc_block_hash
    end

    validator = b.validator(@store)
    validator.validate.should == false
    validator.error.should == error
  end

  it "1. Check syntactic correctness" do
    block = create_block @block1.hash, false
    block.hash = "00" * 32
    block.bits = Bitcoin.network[:proof_of_work_limit]
    validator = block.validator(@store)
    validator.validate.should == false
    validator.error.should == [:hash, ["00"*32, block.hash]]
  end

  it "3. Transaction list must be non-empty" do
    check_block(@block, [:tx_list, 0]) {|b| b.tx = [] }
  end

  it "4. Block hash must satisfy claimed nBits proof of work" do
    @block.bits = Bitcoin.encode_compact_bits("0000#{"ff" * 30}")
    @block.recalc_block_hash
    target = Bitcoin.decode_compact_bits(@block.bits).to_i(16)
    check_block(@block, [:bits, [@block.hash.to_i(16), target]])
  end

  it "5. Block timestamp must not be more than two hours in the future" do
    fake_time = (Time.now + 3 * 60 * 60).to_i
    check_block(@block, [:max_timestamp, [fake_time, Time.now.to_i + 7200]]) {|b|
      b.time = fake_time }
  end

  it "6. First transaction must be coinbase (i.e. only 1 input, with hash=0, n=-1), the rest must not be" do
    block = create_block @block1.hash, false, [
      ->(tx) { create_tx(tx, @block1.tx.first, 0, [[50, @key]]) } ], @key
    check_block(block, [:coinbase, [0, 1]]) {|b| b.tx = b.tx.reverse }
    check_block(block, [:coinbase, [1, 1]]) {|b| b.tx << b.tx[0] }
  end

  it "8. For the coinbase (first) transaction, scriptSig length must be 2-100" do
    check_block(@block, [:coinbase_scriptsig, [1, 2, 100]]) {|b|
      b.tx[0].in[0].script_sig = "\x01" }
    check_block(@block, [:coinbase_scriptsig, [101, 2, 100]]) {|b|
      b.tx[0].in[0].script_sig = "\x01" * 101 }
  end

  it "10. Verify Merkle hash" do
    check_block(@block, [:mrkl_root, ["00"*32, @block.mrkl_root.reverse_hth]]) {|b|
      b.mrkl_root = "\x00" * 32 }
  end

  it "12. Check that nBits value matches the difficulty rules" do
    block = create_block @block1.hash, false, [], @key
    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("0000#{"ff"*30}")
    validator = block.validator(@store)
    validator.validate.should == false
    validator.error.should == [:difficulty, [553713663, 520159231]]
  end

  it "13. Reject if timestamp is the median time of the last 11 blocks or before" do
    prev_block = @block1
    12.times do |i|
      prev_block = create_block(prev_block.hash, false, [])
      prev_block.time = i
      prev_block.recalc_block_hash
      @store.store_block(prev_block).should == [i+2, 0]
    end

    block = create_block(prev_block.hash, false, [], @key)

    fake_time = @store.get_block_by_depth(8).time - 1
    times = @store.db[:blk].where("depth > 2").map{|b|b[:time]}.sort
    m, r = times.size.divmod(2)
    min_time = (r == 0 ? times[m-1, 2].inject(:+) / 2.0 : times[m])

    # reject before median time
    check_block(block, [:min_timestamp, [fake_time, min_time]]) {|b| b.time = fake_time }

    # reject at exactly median time
    fake_time = @store.get_block_by_depth(8).time
    check_block(block, [:min_timestamp, [fake_time, fake_time]]) {|b| b.time = fake_time }

    # accept after median time
    block.time = @store.get_block_by_depth(8).time + 1; block.recalc_block_hash
    @store.store_block(block).should == [14, 0]
  end

  it "should allow chains of unconfirmed transactions" do
    tx1 = build_tx {|t| create_tx(t, @block1.tx.first, 0, [[50, @key]]) }
    tx2 = build_tx {|t| create_tx(t, tx1, 0, [[50, @key]]) }
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

    Bitcoin::REWARD_DROP = 2
    block4 = create_block(block2.hash, false, [], @key, 50e8)
    -> { @store.store_block(block4) }.should.raise(ValidationError)

    block5 = create_block(block2.hash, false, [], @key, 25e8)
    @store.store_block(block5).should == [3, 0]
    Bitcoin::REWARD_DROP = 210_000
  end

end

describe "transaction rules (#{options[0]} - #{options[1]})" do

  before do
    Bitcoin.network = :spec
    @store = storage
    @store.reset
    @store.log.level = :warn

    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("f"*64)
    @key = Bitcoin::Key.generate
    @block0 = create_block "00"*32, false, [], @key
    Bitcoin.network[:genesis_hash] = @block0.hash
    @store.store_block(@block0)
    @store.get_head.should == @block0
    @block1 = create_block @block0.hash, true, [], @key
    @store.get_head.should == @block1
    @tx = build_tx {|t| create_tx(t, @block1.tx.first, 0, [[50, @key]]) }
  end

  def check_tx tx, error
    t = tx.dup
    yield(t) && t.instance_eval { @hash = generate_hash(to_payload) }  if block_given?
    validator = t.validator(@store)
    validator.validate.should == false
    validator.error.should == error
  end

  it "should validate" do
    validator = @tx.validator(@store)
    validator.validate.should == true
    validator.validate(raise_errors: true).should == true
    hash = @tx.hash; @tx.instance_eval { @hash = "f"*64 }
    validator = @tx.validator(@store)
    validator.validate.should == false
    validator.error.should == [:hash, ["f"*64, hash]]
    -> { validator.validate(raise_errors: true) }.should.raise(ValidationError)
  end

  it "1. Check syntactic correctness" do
    hash = @tx.hash; @tx.instance_eval { @hash = "ff"*32 }
    validator = @tx.validator(@store)
    validator.validate.should == false
    validator.error.should == [:hash, ["ff"*32, hash]]
  end

  it "2. Make sure neither in or out lists are empty" do
    check_tx(@tx, [:lists, [0, 1]]) {|tx| tx.instance_eval { @in = [] } }
    check_tx(@tx, [:lists, [1, 0]]) {|tx| tx.instance_eval { @out = [] } }
  end

  it "3. Size in bytes < MAX_BLOCK_SIZE" do
    max = Bitcoin::MAX_BLOCK_SIZE; Bitcoin::MAX_BLOCK_SIZE = 1000
    check_tx(@tx, [:max_size, [@tx.payload.bytesize+978, 1000]]) {|tx|
      tx.out[0].pk_script = "\x00" * 1001 }
    Bitcoin::MAX_BLOCK_SIZE = max
  end

  it "4. Each output value, as well as the total, must be in legal money range" do
    check_tx(@tx, [:output_values, [Bitcoin::network[:max_money] + 1, Bitcoin::network[:max_money]]]) {|tx|
      tx.out[0].value = Bitcoin::network[:max_money] + 1 }
  end

  it "5. Make sure none of the inputs have hash=0, n=-1" do
    check_tx(@tx, [:inputs, [0]]) do |tx|
      tx.in.first.prev_out = "\x00"*32
      tx.in.first.prev_out_index = 4294967295
    end
  end

  it "6. Check that nLockTime <= UINT32_MAX, size in bytes >= 100, and sig opcount <= 2" do
    check_tx(@tx, [:lock_time, [Bitcoin::UINT32_MAX + 1, Bitcoin::UINT32_MAX]]) {|tx| tx.lock_time = Bitcoin::UINT32_MAX + 1 }
    # TODO: validate sig opcount
  end

  # it "7. Reject 'nonstandard' transactions: scriptSig doing anything other than pushing numbers on the stack, or scriptPubkey not matching the two usual forms" do
  #   check_tx(@tx, /standard/) {|tx| tx.out[0].pk_script = Bitcoin::Script.from_string("OP_ADD OP_DUP OP_DROP").raw }
  # end

  # it "9. Reject if any other tx in the pool uses the same transaction output as one used by this tx." do
  # end

  it "11. For each input, if we are using the nth output of the earlier transaction, but it has fewer than n+1 outputs, reject this transaction" do
    check_tx(@tx, [:prev_out, [[@tx.in[0].prev_out.reverse_hth, 2]]]) {|tx| tx.in[0].prev_out_index = 2 }
  end

  it "13. Verify crypto signatures for each input; reject if any are bad" do
    check_tx(@tx, [:signatures, [0]]) {|tx| @tx.in[0].script_sig = "bad sig" }
  end

  it "14. For each input, if the referenced output has already been spent by a transaction in the main branch, reject this transaction" do
    block2 = create_block(@block1.hash, true, [
        ->(tx) {create_tx(tx, @block1.tx.first, 0, [[50, @key]])}], @key)
    if @store.class.name =~ /Utxo/
      check_tx(@tx, [:prev_out, [[@tx.in[0].prev_out.reverse_hth, 0]]])
    else
      check_tx(@tx, [:not_spent, [0]])
    end
  end
  
  it "15. Using the referenced output transactions to get input values, check that each input value, as well as the sum, are in legal money range" do
    @store.db[@store.class.name =~ /Utxo/ ? :utxo : :txout].order(:id).reverse.limit(1).update(value: 22e14)
    check_tx(@tx, [:input_values, [22e14, 21e14]])
  end

  it "16. Reject if the sum of input values < sum of output values" do
    tx = build_tx {|t| create_tx(t, @block1.tx.first, 0, [[100e8, @key]]) }
    check_tx(tx, [:output_sum, [100e8, 50e8]])
  end


  it "should not allow double spend within the same block" do
    # double-spend output from previous block
    prev_tx = @block1.tx[0]
    block = create_block @block1.hash, false, [
     ->(t) { create_tx(t, prev_tx, 0, [[prev_tx.out[0].value, @key]]) },
     ->(t) { create_tx(t, prev_tx, 0, [[prev_tx.out[0].value, @key]]) }
    ]
    -> { @store.store_block(block) }.should.raise(Bitcoin::Validation::ValidationError)

    # double-spend output from current block
    block = create_block @block1.hash, false, [
      ->(t) { create_tx(t, prev_tx, 0, [[prev_tx.out[0].value, @key]]) }
    ]
    prev_tx = block.tx[1]
    block.tx << build_tx {|t| create_tx(t, prev_tx, 0, [[prev_tx.out[0].value, @key]]) }
    block.tx << build_tx {|t| create_tx(t, prev_tx, 0, [[prev_tx.out[0].value, @key]]) }
    block.recalc_mrkl_root; block.recalc_block_hash
    -> { @store.store_block(block) }.should.raise(Bitcoin::Validation::ValidationError)
  end

end

end
