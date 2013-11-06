# encoding: ascii-8bit

require_relative '../spec_helper'

include Bitcoin::Builder



[ { :name => :utxo, :db => 'sqlite:/', :index_all_addrs => true },
  { :name => :sequel, :db => 'sqlite:/' } ] .each do |configuration|

  describe "reorg (#{configuration[:name].capitalize}Store)" do

  def balance addr
    @store.get_balance(Bitcoin.hash160_from_address(addr))
  end

  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.send(configuration[:name], configuration)
    @store.reset
    def @store.in_sync?; true; end
    @store.log.level = :warn
    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("ff"*32)
    @key = Bitcoin::Key.generate
    @block0 = create_block "00"*32, false, [], @key
    Bitcoin.network[:genesis_hash] = @block0.hash
    @store.store_block(@block0)
    @store.get_head.should == @block0
  end

  it "should retarget" do
    @store.reset
    time = Time.now.to_i - 3000*600

    Bitcoin::Validation::Block::RETARGET = 10

    # create genesis block
    block = create_block "00"*32, false, [], @key, 50e8, {time: time}
    Bitcoin.network[:genesis_hash] = block.hash
    @store.store_block(block)
    time += 600

    # create too fast blocks
    block = create_blocks block.hash, 9, time: time, interval: 10
    time += 90

    -> { create_blocks block.hash, 1, time: time }
      .should.raise(Bitcoin::Validation::ValidationError).message.should =~ /difficulty/

    block = create_blocks block.hash, 1, time: time, bits: bits = 541065152
    @store.get_head.should == block
    time += 600

    # create too slow blocks
    block = create_blocks block.hash, 9, time: time, interval: 6000, bits: bits
    time += 8*6000
    -> { create_blocks block.hash, 1, time: time, bits: bits }
      .should.raise(Bitcoin::Validation::ValidationError).message.should =~ /difficulty/

    block = create_blocks block.hash, 1, bits: 553713663
    @store.get_head.should == block
  end

  it "should reorg across a retargetting boundary correctly" do
    @store.reset
    time = Time.now.to_i - 3000*600

    # create genesis block
    block = create_block "00"*32, false, [], @key, 50e8, {time: time}
    time += 600
    Bitcoin.network[:genesis_hash] = block.hash
    @store.store_block(block)

    # create first regular block
    split_block = create_blocks block.hash, 1, time: time
    split_time = time + 600

    # create branch A with target interval
    block_a = create_blocks split_block.hash, 8, time: split_time
    time_a = split_time + 8 * 600

    # create branch B with faster-than-target interval
    block_b = create_blocks split_block.hash, 8, time: split_time, interval: 60
    time_b = split_time + 8 * 60

    # create 2 blocks for branch A with regular difficulty
    block_a = create_blocks block_a.hash, 2, time: time_a

    # create 1 block for branch B at higher difficulty
    block_b = create_blocks block_b.hash, 1, time: time_b, bits: 541568460

    # check that shorter branch B has overtaken longer branch A due to more work
    @store.get_head.hash.should == block_b.hash
  end

  it "should reorg a single side block" do
    @store.get_head.should == @block0

    block1 = create_block @block0.hash
    @store.get_head.should == block1

    block2_0 = create_block block1.hash
    @store.get_head.should == block2_0

    block2_1 = create_block block1.hash
    @store.get_head.should == block2_0

    block3 = create_block block2_1.hash
    @store.get_head.should == block3
    @store.get_block_by_depth(2).hash.should == block2_1.hash
  end

  it "should reorg two side blocks" do
    block1 = create_block @block0.hash
    @store.get_head.should == block1

    block2_0 = create_block block1.hash
    @store.get_head.should == block2_0

    block2_1 = create_block block1.hash
    @store.get_head.should == block2_0

    block3_1 = create_block block2_1.hash
    @store.get_head.should == block3_1

    block3_0 = create_block block2_0.hash
    @store.get_head.should == block3_1

    block4 = create_block block3_0.hash
    @store.get_head.should == block4
  end

  it "should reconnect orphans" do
    next(true.should == true)  if @store.class.name =~ /Utxo/
    blocks = [@block0]
    3.times { blocks << create_block(blocks.last.hash, false) }

    {
      [0, 1, 2, 3] => [0, 1, 2, 3],
      [0, 1, 3, 2] => [0, 1, 1, 3],
      [0, 3, 2, 1] => [0, 0, 0, 3],
      [0, 3, 1, 2] => [0, 0, 1, 3],
      [0, 2, 3, 1] => [0, 0, 0, 3],
    }.each do |order, result|
      @store.reset
      order.each_with_index do |n, i|
        @store.store_block(blocks[n])
        @store.get_head.should == blocks[result[i]]
      end
    end

    i = 3; (0..i).to_a.permutation.each do |order|
      @store.reset
      order.each {|n| @store.store_block(blocks[n]) }
      @store.get_head.should == blocks[i]
    end
  end

  it "should handle existing blocks" do
    Bitcoin.network = :testnet
    blocks = [@block0]
    3.times { blocks << create_block(blocks.last.hash, false) }
    blocks[1..-1].each.with_index {|b, idx| @store.store_block(b).should == [idx+1, 0] }
    3.times {|i| @store.store_block(blocks[i]).should == [i] }
    @store.get_head.should == blocks[-1]
  end

  # see https://bitcointalk.org/index.php?topic=46370.0
  it "should pass reorg unit tests" do
    class Bitcoin::Validation::Block; def difficulty; true; end; end
    Bitcoin.network = :bitcoin
    @store.import "./spec/bitcoin/fixtures/reorg/blk_0_to_4.dat"
    @store.get_depth.should == 4
    @store.get_head.hash.should =~ /000000002f264d65040/
    balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").should == 10000000000
    balance("1NiEGXeURREqqMjCvjCeZn6SwEBZ9AdVet").should == 0
    balance("1KXFNhNtrRMfgbdiQeuJqnfD7dR4PhniyJ").should == 5000000000
    balance("1JyMKvPHkrCQd8jQrqTR1rBsAd1VpRhTiE").should == 10000000000
    @store.import "./spec/bitcoin/fixtures/reorg/blk_3A.dat"
    @store.import "./spec/bitcoin/fixtures/reorg/blk_4A.dat"
    @store.get_head.hash.should =~ /000000002f264d65040/
    @store.import "./spec/bitcoin/fixtures/reorg/blk_5A.dat"
    @store.get_depth.should == 5
    @store.get_head.hash.should =~ /00000000195f85184e7/
    balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").should == 15000000000
    balance("1NiEGXeURREqqMjCvjCeZn6SwEBZ9AdVet").should == 1000000000
    balance("1KXFNhNtrRMfgbdiQeuJqnfD7dR4PhniyJ").should == 0
    balance("1JyMKvPHkrCQd8jQrqTR1rBsAd1VpRhTiE").should == 14000000000
    class Bitcoin::Validation::Block
      def difficulty
        return true  if Bitcoin.network_name == :testnet3
        block.bits == next_bits_required || [block.bits, next_bits_required]
      end
    end
  end

end
end
