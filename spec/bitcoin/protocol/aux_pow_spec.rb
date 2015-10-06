# encoding: ascii-8bit

require_relative '../spec_helper.rb'

include Bitcoin

describe Bitcoin::Protocol::AuxPow do

  before do
    Bitcoin.network = :namecoin
    @data = fixtures_file("rawblock-auxpow.bin")
    @blk = P::Block.new(@data)
    @aux_pow = @blk.aux_pow
  end

  it "should parse AuxPow" do
    @aux_pow.should != nil
    @aux_pow.block_hash.hth.should ==
      "b42124fd99e67ddabe52ebbfcb30a82b8c74268a320b3c5e2311000000000000"
    @aux_pow.coinbase_branch.should == [
      "c22f79ba86968a5285225008b2740f074f44f44ef27b8efb61ecff09e9eb4f6d",
      "99696473beb0caa79d4209dbaa6e18fdc23ebdc67210f86fec0c4559847252d0",
      "20cbcff309ec8c267892a476c1b22d23d9e5d7a6fdfd025658de6c2ae4e7c564",
      "e4317593d6ad8d735ded56c336376b7409207c3ea6b92b2451f79eced606944e" ]
    @aux_pow.coinbase_index.should == 0
    @aux_pow.chain_branch.should == []
    @aux_pow.chain_index.should == 0
    @aux_pow.parent_block.hash.should ==
      "00000000000011235e3c0b328a26748c2ba830cbbfeb52beda7de699fd2421b4"
  end

  it "#to_payload" do
    @blk.to_payload.should == @data
    P::Block.new(@blk.to_payload).to_payload.should == @data
  end

  it "#to_hash" do
    P::Block.from_hash(@blk.to_hash).to_payload.should == @data
  end

  it "#to_json" do
    P::Block.from_json(@blk.to_json).to_payload.should == @data
  end

end
