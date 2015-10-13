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
      'testnet-265322' => fixtures_file('rawblock-testnet-265322.bin'),
    }
  end

  it '#new' do
    proc{
      Block.new( nil )
      @block = Block.new( @blocks['0'] )
    }.should.not.raise Exception

    proc{
      Block.new( @blocks['0'][0..20] )
    }.should.raise Exception

    block = Block.new(nil)
    block.parse_data(@blocks['0']).should == true
    block.header_info[7].should == 215
    block.to_payload.should == @blocks['0']

    block = Block.new(nil)
    block.parse_data(@blocks['0'] + "AAAA").should == "AAAA"
    block.header_info[7].should == 215
    block.to_payload.should == @blocks['0']
  end

  it '#hash' do
    @block.hash.should == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
  end

  it '#tx' do
    @block.tx.size.should == 1
    @block.tx[0].is_a?(Tx).should == true
    @block.tx[0].hash.should == "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
  end

  it '#to_hash' do
    @block.to_hash.keys.should == ["hash", "ver", "prev_block", "mrkl_root", "time", "bits", "nonce", "n_tx", "size", "tx", "mrkl_tree"]
  end

  it '#to_json' do
    @block.to_json.should == fixtures_file('rawblock-0.json')
    Block.new( @blocks['1'] ).to_json.should == fixtures_file('rawblock-1.json')
    Block.new( @blocks['131025'] ).to_json.should == fixtures_file('rawblock-131025.json')
    Block.new( @blocks['testnet-26478'] ).to_json.should == fixtures_file('rawblock-testnet-26478.json')
    Block.from_json(@block.to_json).tx[0].in[0].sequence.should == "\xff\xff\xff\xff"
  end

  it '#to_payload' do
    @block.to_payload.should == @block.payload
    Block.new( @block.to_payload ).to_payload.should == @block.payload
    Block.new( @blocks['1'] ).to_payload.should == @blocks['1']
    Block.new( @blocks['131025'] ).to_payload.should == @blocks['131025']
    Block.new( @blocks['testnet-26478'] ).to_payload.should == @blocks['testnet-26478']
  end

  describe "Block.from_json" do

    it 'should load blocks from json' do
      block = Block.from_json(fixtures_file('rawblock-0.json'))
      block.to_payload.should == @blocks['0']
      block.tx[0].in[0].sequence.should == "\xff\xff\xff\xff"
      Block.from_json(fixtures_file('rawblock-1.json')).to_payload.should == @blocks['1']
   
      Block.from_json(fixtures_file('rawblock-131025.json'))
        .to_payload.should == @blocks['131025']
   
      Block.from_json(fixtures_file('rawblock-testnet-26478.json'))
        .to_payload.should == @blocks['testnet-26478']

      # testnet3 block 0000000000ac85bb2530a05a4214a387e6be02b22d3348abc5e7a5d9c4ce8dab
      block_raw = fixtures_file('block-testnet-0000000000ac85bb2530a05a4214a387e6be02b22d3348abc5e7a5d9c4ce8dab.bin')
      Block.new(block_raw).to_payload.should == block_raw
      # Block.from_json(Block.new(block_raw).to_json).to_payload.should == block_raw # slow test
    end

    it "should work with litecoin blocks" do
      Bitcoin.network = :litecoin # change to litecoin
      litecoin_block = "litecoin-genesis-block-12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"
      Block.from_json(fixtures_file(litecoin_block + '.json'))
        .to_payload.should == fixtures_file(litecoin_block + '.bin')

      json = Block.new(fixtures_file(litecoin_block + '.bin')).to_json
      Block.from_json(json)
        .to_payload.should == fixtures_file(litecoin_block + '.bin')
      Block.from_json(json).hash == litecoin_block.split("-").last

      litecoin_block = "litecoin-block-80ca095ed10b02e53d769eb6eaf92cd04e9e0759e5be4a8477b42911ba49c78f"
      Block.from_json(fixtures_file(litecoin_block + '.json'))
        .to_payload.should == fixtures_file(litecoin_block + '.bin')

      json = Block.new(fixtures_file(litecoin_block + '.bin')).to_json
      Block.from_json(json)
        .to_payload.should == fixtures_file(litecoin_block + '.bin')
      Block.from_json(json).hash == litecoin_block.split("-").last
      Bitcoin.network = :bitcoin
    end

    it 'should check block hash' do
      block = Block.from_json(fixtures_file('rawblock-0.json'))
      h = block.to_hash
      h['hash'][0] = "1"
      -> { Block.from_hash(h) }.should.raise(Exception)
        .message.should == "Block hash mismatch! Claimed: 10000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048, Actual: 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    end

    it "should check merkle tree" do
      block = Block.from_json(fixtures_file('rawblock-0.json'))
      h = block.to_hash
      h['tx'][0]['ver'] = 2
      h['tx'][0]['hash'] = "5ea04451af738d113f0ae8559225b7f893f186f099d88c72230a5e19c0bb830d"
      -> { Block.from_hash(h) }.should.raise(Exception)
        .message.should.include?("Block merkle root mismatch!")
    end

  end

  it '#header_to_json' do
    @block.header_to_json.should == (<<-JSON).chomp
{
  "hash":"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
  "ver":1,
  "prev_block":"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  "mrkl_root":"0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
  "time":1231469665,
  "bits":486604799,
  "nonce":2573394689,
  "n_tx":1,
  "size":215
}
    JSON
  end

  it '#verify_mrkl_root' do
    block0 = Block.from_json(fixtures_file('rawblock-0.json'))
    block1 = Block.from_json(fixtures_file('rawblock-1.json'))
    block0.tx.size.should == 1
    block0.verify_mrkl_root.should == true
    block0.tx << block.tx.last # test against CVE-2012-2459
    block0.verify_mrkl_root.should == false
    block0.tx = block1.tx
    block0.verify_mrkl_root.should == false
  end

  it '#bip34_block_height' do
    # block version 1
    block = Block.from_json(fixtures_file('rawblock-131025.json'))
    block.ver.should == 1
    block.bip34_block_height.should == nil
    # block version 2 (introduced by BIP_0034)
    block = Block.from_json(fixtures_file('000000000000056b1a3d84a1e2b33cde8915a4b61c0cae14fca6d3e1490b4f98.json'))
    block.ver.should == 2
    block.bip34_block_height.should == 197657
  end

  it 'should work with huge block version' do
    Bitcoin::P::Block.new(@blocks['testnet-265322']).hash.should ==
      "0000000000014b351588a177be099e39afd4962cd3d58e9ab5cbe45a9cf83c8a"
  end

end
