require_relative '../spec_helper.rb'

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
    tx.binary_hash.should == "\xB4\x02-\x9F\xE5(\xFB\x90pP\x01\x16K\f\xC3\xA8\xF5\xA1\x9C\xB8\xED\x02\xBF\xD4\xFC,\xB6%f\xD1\x9Dn"
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

    tx = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin') )
    tx.to_json.should == fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json')
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

  it '#sign_input_signature' do
    prev_tx = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin') )
    prev_tx.hash.should == "2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a"

    key = Bitcoin.open_key("56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc",
      pubkey="04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3")
    new_tx = Bitcoin::Protocol::Tx.new(nil)
    new_tx.add_in( [prev_tx.binary_hash, 0, 0] )
    pk_script = Bitcoin::Script.to_address_script("1BVJWLTCtjA8wRivvrCiwjNdL6KjdMUCTZ")
    new_tx.add_out( [1000000, pk_script.bytesize, pk_script] )
    signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
    sig = Bitcoin.sign_data(key, signature_hash)
    script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [pubkey].pack("H*"))
    new_tx.in[0][2] = script_sig.bytesize
    new_tx.in[0][3] = script_sig

    new_tx = Bitcoin::Protocol::Tx.new( new_tx.to_payload )
    new_tx.hash.should != nil
    new_tx.verify_input_signature(0, prev_tx).should == true



    prev_tx = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984.bin') )
    prev_tx.hash.should == "14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984"

    key = Bitcoin.open_key("115ceda6c1e02d41ce65c35a30e82fb325fe3f815898a09e1a5d28bb1cc92c6e",
            pubkey="0409d103127d26ce93ee41f1b9b1ed4c1c243acf48e31eb5c4d88ad0342ccc010a1a8d838846cf7337f2b44bc73986c0a3cb0568fa93d068b2c8296ce8d47b1545")
    new_tx = Bitcoin::Protocol::Tx.new(nil)
    new_tx.add_in( [prev_tx.binary_hash, 0, 0] )
    pk_script = Bitcoin::Script.to_address_script("1FEYAh1x5jeKQMPPuv3bKnKvbgVAqXvqjW")
    new_tx.add_out( [1000000, pk_script.bytesize, pk_script] )
    signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
    sig = Bitcoin.sign_data(key, signature_hash)
    script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [pubkey].pack("H*"))
    new_tx.in[0][2] = script_sig.bytesize
    new_tx.in[0][3] = script_sig

    new_tx = Bitcoin::Protocol::Tx.new( new_tx.to_payload )
    new_tx.hash.should != nil
    new_tx.verify_input_signature(0, prev_tx).should == true



    prev_tx = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin') )
    prev_tx.hash.should == "b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d"

    key = Bitcoin.open_key("56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc",
      pubkey="04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3")
    new_tx = Bitcoin::Protocol::Tx.new(nil)
    new_tx.add_in( [prev_tx.binary_hash, 0, 0] )
    pk_script = Bitcoin::Script.to_address_script("14yz7fob6Q16hZu4nXfmv1kRJpSYaFtet5")
    new_tx.add_out( [1000000, pk_script.bytesize, pk_script] )
    signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
    sig = Bitcoin.sign_data(key, signature_hash)
    script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [pubkey].pack("H*"))
    new_tx.in[0][2] = script_sig.bytesize
    new_tx.in[0][3] = script_sig

    new_tx = Bitcoin::Protocol::Tx.new( new_tx.to_payload )
    new_tx.hash.should != nil
    new_tx.verify_input_signature(0, prev_tx).should == true

    #File.open("rawtx-#{new_tx.hash}.bin",'wb'){|f| f.print new_tx.to_payload }
    prev_tx = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-52250a162c7d03d2e1fbc5ebd1801a88612463314b55102171c5b5d817d2d7b2.bin') )
    prev_tx.hash.should == "52250a162c7d03d2e1fbc5ebd1801a88612463314b55102171c5b5d817d2d7b2"
    #File.open("rawtx-#{prev_tx.hash}.json",'wb'){|f| f.print prev_tx.to_json }
  end
end
