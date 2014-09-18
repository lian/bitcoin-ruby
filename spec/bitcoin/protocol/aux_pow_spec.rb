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
    @aux_pow.branch.map(&:hth).should == [
      "6d4febe909ffec61fb8e7bf24ef4444f070f74b208502285528a9686ba792fc2",
      "d052728459450cec6ff81072c6bd3ec2fd186eaadb09429da7cab0be73646999",
      "64c5e7e42a6cde585602fdfda6d7e5d9232db2c176a49278268cec09f3cfcb20",
      "4e9406d6ce9ef751242bb9a63e7c2009746b3736c356ed5d738dadd6937531e4" ]
    @aux_pow.mrkl_index.should == 0
    @aux_pow.aux_branch.should == []
    @aux_pow.aux_index.should == 0
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
