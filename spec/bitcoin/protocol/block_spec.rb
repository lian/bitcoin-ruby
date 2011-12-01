require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Tx' do

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


  it '#new' do
    proc{
      Bitcoin::Protocol::Block.new( nil )
      @block = Bitcoin::Protocol::Block.new( @blocks['0'] )
    }.should.not.raise Exception

    proc{
      Bitcoin::Protocol::Block.new( @blocks['0'][0..20] )
    }.should.raise Exception
  end

  it '#hash' do
    @block.hash.should == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
  end

  it '#tx' do
    @block.tx.size.should == 1
    @block.tx[0].is_a?(Bitcoin::Protocol::Tx).should == true
    @block.tx[0].hash.should == "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
  end

  it '#to_hash' do
    @block.to_hash.keys.should == ["hash", "ver", "prev_block", "mrkl_root", "time", "bits", "nonce", "n_tx", "size", "tx", "mrkl_tree"]
  end

  it '#to_json' do
    @block.to_json.should == fixtures_file('rawblock-0.json')
    Bitcoin::Protocol::Block.new( @blocks['1'] ).to_json.should == fixtures_file('rawblock-1.json')
    Bitcoin::Protocol::Block.new( @blocks['131025'] ).to_json.should == fixtures_file('rawblock-131025.json')
    Bitcoin::Protocol::Block.new( @blocks['testnet-26478'] ).to_json.should == fixtures_file('rawblock-testnet-26478.json')
  end
end
