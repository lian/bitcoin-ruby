# encoding: ascii-8bit

require_relative '../spec_helper.rb'
include Bitcoin::Protocol

describe 'Bitcoin::Protocol::Block' do

  before do
    @blocks = {
      # block 0:  00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
      '0' => fixtures_file('rawblock-0.bin'),
      # block 1:  000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
      '1' => fixtures_file('rawblock-1.bin'),
      # block 9:  000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805
      '9' => fixtures_file('rawblock-9.bin'),
      # block 170:  00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
      '170' => fixtures_file('rawblock-170.bin'),
      # block 131025:  00000000000007d938dbdd433c5ae12a782de74abf7f566518bc2b2d0a1df145
      '131025' => fixtures_file('rawblock-131025.bin'),
      # block 26478:  000000000214a3f06ee99a033a7f2252762d6a18d27c3cd8c8fe2278190da9f3
      'testnet-26478' => fixtures_file('rawblock-testnet-26478.bin'),
    }
    @data = "02000000415c54dfd2fc920c3b273885eb8055816c3421fac614372f246a120000000000b61176f9f21ea1e4785ca855c728ec7873d3568d9715395149d97035ff61ab665b1f40528a84001c58596e8902000000024e99f644670144736982bfae805a176c2caa5f9fd4e4a728e82eca2d1fa3312caa8ff248d2e487bbc589c03d127ae3272bf4a7717fd3c5011cfb63249478b2d10107".htb
  end

  it "should parse merkle block" do
    block = Bitcoin::P::MerkleBlock.new(@data)
    block.hash.should == "0000000000608a9dcb30f40dfcf2b95ef407fad779a04e7a08130faa38d995e4"
    block.prev_block.reverse.hth.should == "0000000000126a242f3714c6fa21346c815580eb8538273b0c92fcd2df545c41"
    block.mrkl_root.hth.should == "b61176f9f21ea1e4785ca855c728ec7873d3568d9715395149d97035ff61ab66"
    block.time.should == 1379934043
    block.bits.should == 469795978
    block.nonce.should == 2305710424
    block.tx.should == []
    block.tx_count.should == 2
    block.hashes.should == [
      "2c31a31f2dca2ee828a7e4d49f5faa2c6c175a80aebf82697344016744f6994e",
      "d1b278942463fb1c01c5d37f71a7f42b27e37a123dc089c5bb87e4d248f28faa" ]
    block.flags.should == [7]
  end

  it "should parse merkle block from full block data" do
    b = Bitcoin::P::Block.new(@blocks['0'])
    block = Bitcoin::P::MerkleBlock.from_block(b)
    block.hash.should == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    block.tx_count.should == 1
    block.hashes.should == ["0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"]
    block.flags.should == [0]
  end

  it "should serialize merkle block" do
    block = Bitcoin::P::MerkleBlock.new(@data)
    block.to_payload.should == @data
    b = Bitcoin::P::MerkleBlock.new(block.to_payload)
    b.recalc_block_hash
    b.hash.should == block.hash
  end

  it "should convert block to merkle block" do
    block = Bitcoin::P::Block.new(@blocks['0'])
    merkle_block = Bitcoin::P::MerkleBlock.from_block(block)
    merkle_block.hash.should == block.hash
    merkle_block.hashes.should == block.tx.map(&:hash)
  end

end
