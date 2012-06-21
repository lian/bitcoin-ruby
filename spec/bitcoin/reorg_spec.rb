require_relative 'spec_helper'

include Bitcoin::Builder

describe "reorg" do

  def create_block prev, store = true
    block = blk do |b|
      b.prev_block prev
      b.tx do |t|
        t.input {|i| i.coinbase }
        t.output do |o|
          o.value 5000000000
          o.script {|s| s.type :address; s.recipient Bitcoin::Key.generate.addr }
        end
      end
    end
    @store.store_block(block)  if store
    block
  end

  def balance addr
    @store.get_balance(Bitcoin.hash160_from_address(addr))
  end

  before do
    Bitcoin.network = :testnet
    @store = Bitcoin::Storage.sequel(:db => "sqlite:/")
    @store.log.level = :warn
    @block0 = Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin'))
    @store.store_block(@block0)
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
    3.times do
      @store.store_block(blocks[1]).should == [1, 0]
      @store.store_block(blocks[2]).should == [2, 0]
      @store.get_head.should == blocks[2]
    end
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
