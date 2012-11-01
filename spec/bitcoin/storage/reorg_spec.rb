require_relative '../spec_helper'

include Bitcoin::Builder

describe "reorg" do

  def balance addr
    @store.get_balance(Bitcoin.hash160_from_address(addr))
  end

  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.sequel(:db => "sqlite:/")
    def @store.in_sync?; true; end
    @store.log.level = :warn
    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("f"*64)
    @key = Bitcoin::Key.generate
    @block0 = create_block "00"*32, false, [], @key
    Bitcoin.network[:genesis_hash] = @block0.hash
    @store.store_block(@block0)
    @store.get_head.should == @block0
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
  end

end
