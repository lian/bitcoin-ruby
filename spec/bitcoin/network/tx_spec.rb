require_relative '../spec_helper.rb'

require 'bitcoin/network'

describe 'Bitcoin::Protocol::Tx' do

  @payload = [
    fixtures_file('rawtx-01.bin'),
    fixtures_file('rawtx-02.bin'),
    fixtures_file('rawtx-03.bin'),
  ]

  @json = [
    fixtures_file('rawtx-01.json'),
    fixtures_file('rawtx-02.json'),
    fixtures_file('rawtx-03.json')
  ]


  it '#new' do
    proc{
      Bitcoin::Protocol::Tx.new( nil )
      @payload.each{|payload| Bitcoin::Protocol::Tx.new( payload ) }
    }.should.not.raise Exception

    proc{
      Bitcoin::Protocol::Tx.new( @payload[0][0..20] )
    }.should.raise Exception
  end

  it '#parse_data' do
    tx = Bitcoin::Protocol::Tx.new( nil )

    tx.hash.should == nil
    tx.parse_data( @payload[0] ).should == true
    tx.hash.size.should == 64

    tx = Bitcoin::Protocol::Tx.new( nil )
    tx.parse_data( @payload[0] + "AAAA" ).should == "AAAA"
    tx.hash.size.should == 64
  end

  it '#hash' do
    tx = Bitcoin::Protocol::Tx.new( @payload[0] )
    tx.hash.size.should == 64
    tx.hash.should == "6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb28e59f2d02b4"
  end

  it '#to_payload' do
    tx = Bitcoin::Protocol::Tx.new( @payload[0] )
    tx.to_payload.size.should == @payload[0].size
    tx.to_payload.should      == @payload[0]
  end

  it '#to_hash' do
    tx = Bitcoin::Protocol::Tx.new( @payload[0] )
    tx.to_hash.keys.should == ["hash", "ver", "vin_sz", "vout_sz", "lock_time", "size", "in", "out"]
  end

  it '#to_json' do
    tx = Bitcoin::Protocol::Tx.new( @payload[0] )
    tx.to_json.should == @json[0]

    tx = Bitcoin::Protocol::Tx.new( @payload[1] )
    tx.to_json.should == @json[1]

    tx = Bitcoin::Protocol::Tx.new( @payload[2] )
    tx.to_json.should == @json[2]
  end

  it '#verify_input_signature' do
    # transaction-2 of block-170
    tx          = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.bin') )
    tx.hash.should == "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

    # transaction-1 (coinbase) of block-9
    outpoint_tx = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9.bin') )
    outpoint_tx.hash.should == "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"

    tx.verify_input_signature(0, outpoint_tx).should == true
  end
end
