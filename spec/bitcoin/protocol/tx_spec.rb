# encoding: ascii-8bit

require_relative '../spec_helper.rb'

include Bitcoin::Protocol

describe 'Tx' do

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
      Tx.new( nil )
      @payload.each{|payload| Tx.new( payload ) }
    }.should.not.raise Exception

    proc{
      Tx.new( @payload[0][0..20] )
    }.should.raise Exception
  end

  it '#parse_data' do
    tx = Tx.new( nil )

    tx.hash.should == nil
    tx.parse_data( @payload[0] ).should == true
    tx.hash.size.should == 64

    tx = Tx.new( nil )
    tx.parse_data( @payload[0] + "AAAA" ).should == "AAAA"
    tx.hash.size.should == 64
  end

  it '#hash' do
    tx = Tx.new( @payload[0] )
    tx.hash.size.should == 64
    tx.hash.should == "6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb28e59f2d02b4"
    tx.binary_hash.should == "\xB4\x02-\x9F\xE5(\xFB\x90pP\x01\x16K\f\xC3\xA8\xF5\xA1\x9C\xB8\xED\x02\xBF\xD4\xFC,\xB6%f\xD1\x9Dn"
  end

  it '#to_payload' do
    tx = Tx.new( @payload[0] )
    tx.to_payload.size.should == @payload[0].size
    tx.to_payload.should      == @payload[0]
  end

  it '#to_hash' do
    tx = Tx.new( @payload[0] )
    tx.to_hash.keys.should == ["hash", "ver", "vin_sz", "vout_sz", "lock_time", "size", "in", "out"]
  end

  it 'Tx.from_hash' do
    orig_tx = Tx.new( @payload[0] )
    tx = Tx.from_hash( orig_tx.to_hash )
    tx.to_payload.size.should == @payload[0].size
    tx.to_payload.should      == @payload[0]
    tx.to_hash.should == orig_tx.to_hash
    Tx.binary_from_hash( orig_tx.to_hash ).should == @payload[0]
  end

  it 'Tx.binary_from_hash' do
    orig_tx = Tx.new( @payload[0] )
    Tx.binary_from_hash( orig_tx.to_hash ).size.should == @payload[0].size
    Tx.binary_from_hash( orig_tx.to_hash ).should == @payload[0]
  end

  it '#to_json' do
    tx = Tx.new( @payload[0] )
    tx.to_json.should == @json[0]

    tx = Tx.new( @payload[1] )
    tx.to_json.should == @json[1]

    tx = Tx.new( @payload[2] )
    tx.to_json.should == @json[2]

    tx = Tx.new( fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin') )
    tx.to_json.should == fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json')
  end

  it 'Tx.from_json' do
    tx = Tx.from_json( json_string = fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json') )
    tx.to_json.should == json_string

    tx = Tx.from_json( json_string = fixtures_file('rawtx-testnet-a220adf1902c46a39db25a24bc4178b6a88440f977a7e2cabfdd8b5c1dd35cfb.json') )
    tx.to_json.should == json_string

    tx = Tx.from_json( json_string = fixtures_file('rawtx-testnet-e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f.json') )
    tx.to_payload.should == fixtures_file('rawtx-testnet-e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f.bin')
    tx.to_json.should    == json_string

    tx = Tx.from_json( fixtures_file('rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json') )
    Tx.new( tx.to_payload ).to_json.should == tx.to_json
    tx.hash.should == 'ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5'

    # coinbase tx with non-default sequence
    tx = Tx.from_json( json=fixtures_file('0961c660358478829505e16a1f028757e54b5bbf9758341a7546573738f31429.json'))
    Tx.new( tx.to_payload ).to_json.should == json
  end

  it 'Tx.binary_from_json' do
    Tx.binary_from_json( fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json') ).should ==
      fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin')
  end

  it '#verify_input_signature' do
    # transaction-2 of block-170
    tx          = Tx.new( fixtures_file('rawtx-f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.bin') )
    tx.hash.should == "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

    # transaction-1 (coinbase) of block-9
    outpoint_tx = Tx.new( fixtures_file('rawtx-0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9.bin') )
    outpoint_tx.hash.should == "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"

    tx.verify_input_signature(0, outpoint_tx).should == true


    tx = Tx.from_json( fixtures_file('rawtx-c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73.json') )
    tx.hash.should == 'c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73'

    outpoint_tx = Tx.from_json( fixtures_file('rawtx-406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602.json') )
    outpoint_tx.hash.should == '406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602'

    tx.verify_input_signature(0, outpoint_tx).should == true


    tx = Bitcoin::Protocol::Tx.from_json(fixtures_file('0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae.json'))
    tx.hash.should == '0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae'
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(fixtures_file('aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4.json'))
    outpoint_tx.hash.should == 'aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4'
    tx.verify_input_signature(0, outpoint_tx).should == true

    # SIGHASH_ANYONECANPAY transaction
    tx = Bitcoin::Protocol::Tx.from_json(fixtures_file('51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e.json'))
    tx.hash.should == '51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e'
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(fixtures_file('761d8c5210fdfd505f6dff38f740ae3728eb93d7d0971fb433f685d40a4c04f6.json'))
    outpoint_tx.hash.should == '761d8c5210fdfd505f6dff38f740ae3728eb93d7d0971fb433f685d40a4c04f6'
    tx.verify_input_signature(0, outpoint_tx).should == true

    # BIP12/OP_EVAL does't exist.
    tx = Bitcoin::Protocol::Tx.from_json(fixtures_file('03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99.json'))
    tx.hash.should == '03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99'
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(fixtures_file('f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b.json'))
    outpoint_tx.hash.should == 'f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b'
    tx.verify_input_signature(0, outpoint_tx).should == true

    # (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE) p2sh transaction
    tx = Bitcoin::P::Tx.from_json(fixtures_file('7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d.json'))
    tx.hash.should == "7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477.json'))
    outpoint_tx.hash.should == "3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477"
    tx.verify_input_signature(0, outpoint_tx).should == true

    # SIGHHASH_SINGLE - https://bitcointalk.org/index.php?topic=260595.0
    tx = Bitcoin::P::Tx.from_json(fixtures_file('315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f.json'))
    tx.hash.should == "315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('69216b8aaa35b76d6613e5f527f4858640d986e1046238583bdad79b35e938dc.json'))
    outpoint_tx.hash.should == "69216b8aaa35b76d6613e5f527f4858640d986e1046238583bdad79b35e938dc"
    tx.verify_input_signature(0, outpoint_tx).should == true
    tx.verify_input_signature(1, outpoint_tx).should == true
  end

  it '#sign_input_signature' do
    prev_tx = Tx.new( fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin') )
    prev_tx.hash.should == "2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a"

    key = Bitcoin.open_key("56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc",
      pubkey="04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3")
    new_tx = Tx.new(nil)
    new_tx.add_in( TxIn.new(prev_tx.binary_hash, 0, 0) )
    new_tx.add_out( TxOut.value_to_address(1000000, "1BVJWLTCtjA8wRivvrCiwjNdL6KjdMUCTZ") )
    signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
    sig = Bitcoin.sign_data(key, signature_hash)
    new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(sig, [pubkey].pack("H*"))

    new_tx = Tx.new( new_tx.to_payload )
    new_tx.hash.should != nil
    new_tx.verify_input_signature(0, prev_tx).should == true



    prev_tx = Tx.new( fixtures_file('rawtx-14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984.bin') )
    prev_tx.hash.should == "14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984"

    key = Bitcoin.open_key("115ceda6c1e02d41ce65c35a30e82fb325fe3f815898a09e1a5d28bb1cc92c6e",
            pubkey="0409d103127d26ce93ee41f1b9b1ed4c1c243acf48e31eb5c4d88ad0342ccc010a1a8d838846cf7337f2b44bc73986c0a3cb0568fa93d068b2c8296ce8d47b1545")
    new_tx = Tx.new(nil)
    new_tx.add_in( TxIn.new(prev_tx.binary_hash, 0, 0) )
    pk_script = Bitcoin::Script.to_address_script("1FEYAh1x5jeKQMPPuv3bKnKvbgVAqXvqjW")
    new_tx.add_out( TxOut.new(1000000, pk_script) )
    signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
    sig = Bitcoin.sign_data(key, signature_hash)
    new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(sig, [pubkey].pack("H*"))

    new_tx = Tx.new( new_tx.to_payload )
    new_tx.hash.should != nil
    new_tx.verify_input_signature(0, prev_tx).should == true



    prev_tx = Tx.new( fixtures_file('rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin') )
    prev_tx.hash.should == "b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d"

    key = Bitcoin.open_key("56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc",
      pubkey="04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3")
    new_tx = Tx.new(nil)
    new_tx.add_in( TxIn.new(prev_tx.binary_hash, 0, 0) )
    new_tx.add_out( TxOut.value_to_address(1000000, "14yz7fob6Q16hZu4nXfmv1kRJpSYaFtet5") )
    signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
    sig = Bitcoin.sign_data(key, signature_hash)
    new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(sig, [pubkey].pack("H*"))

    new_tx = Tx.new( new_tx.to_payload )
    new_tx.hash.should != nil
    new_tx.verify_input_signature(0, prev_tx).should == true

    #File.open("rawtx-#{new_tx.hash}.bin",'wb'){|f| f.print new_tx.to_payload }
    prev_tx = Tx.new( fixtures_file('rawtx-52250a162c7d03d2e1fbc5ebd1801a88612463314b55102171c5b5d817d2d7b2.bin') )
    prev_tx.hash.should == "52250a162c7d03d2e1fbc5ebd1801a88612463314b55102171c5b5d817d2d7b2"
    #File.open("rawtx-#{prev_tx.hash}.json",'wb'){|f| f.print prev_tx.to_json }
  end

  it '#calculate_minimum_fee' do
    tx = Tx.new( fixtures_file('rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin') )
    tx.minimum_relay_fee.should == 0
    tx.minimum_block_fee.should == 0
    tx = Tx.from_json(fixtures_file('bc179baab547b7d7c1d5d8d6f8b0cc6318eaa4b0dd0a093ad6ac7f5a1cb6b3ba.json'))
    tx.minimum_relay_fee.should == 10_000
    tx.minimum_block_fee.should == 50_000
  end

  describe "Tx - BIP Scripts" do

    it "should do OP_CHECKHASHVERIFY (BIP_0017)" do # https://en.bitcoin.it/wiki/BIP_0017
      # scriptSig: [signatures...] OP_CODESEPARATOR 1 [pubkey1] [pubkey2] 2 OP_CHECKMULTISIG
      # scriptPubKey: [20-byte-hash of {1 [pubkey1] [pubkey2] 2 OP_CHECKMULTISIG} ] OP_CHECKHASHVERIFY OP_DROP

      tx = Tx.from_json(fixtures_file('bc179baab547b7d7c1d5d8d6f8b0cc6318eaa4b0dd0a093ad6ac7f5a1cb6b3ba.json'))
      tx.hash.should == "bc179baab547b7d7c1d5d8d6f8b0cc6318eaa4b0dd0a093ad6ac7f5a1cb6b3ba"

      prev_tx1 = Tx.from_json(fixtures_file('477fff140b363ec2cc51f3a65c0c58eda38f4d41f04a295bbd62babf25e4c590.json'))
      prev_tx1.hash.should == "477fff140b363ec2cc51f3a65c0c58eda38f4d41f04a295bbd62babf25e4c590"

      prev_tx2 = Tx.from_json(fixtures_file('0d0affb5964abe804ffe85e53f1dbb9f29e406aa3046e2db04fba240e63c7fdd.json'))
      prev_tx2.hash.should == "0d0affb5964abe804ffe85e53f1dbb9f29e406aa3046e2db04fba240e63c7fdd"

      tx.verify_input_signature(0, prev_tx1).should == true
      tx.verify_input_signature(1, prev_tx2).should == true
    end

    it "should do OP_CHECKMULTISIG" do
      # checkmultisig without checkhashverify
      tx = Tx.from_json(fixtures_file('23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63.json'))
      prev_tx = Tx.from_json(fixtures_file('60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1.json'))
      tx.verify_input_signature(0, prev_tx).should == true

      # p2sh + multisig transaction from mainnet
      tx      = Tx.from_json( fixtures_file('rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json') )
      prev_tx = Tx.from_json( fixtures_file("rawtx-de35d060663750b3975b7997bde7fb76307cec5b270d12fcd9c4ad98b279c28c.json") )
      tx.verify_input_signature(0, prev_tx).should == true
    end

    it "should do P2SH with inner OP_CHECKMULTISIG (BIP 0016)" do
      tx = Tx.from_json(fixtures_file('3a17dace09ffb919ed627a93f1873220f4c975c1248558b18d16bce25d38c4b7.json'))
      prev_tx = Tx.from_json(fixtures_file('35e2001b428891fefa0bfb73167c7360669d3cbd7b3aa78e7cad125ddfc51131.json'))
      tx.verify_input_signature(0, prev_tx).should == true

      tx = Tx.from_json(fixtures_file('bd1715f1abfdc62bea3f605bdb461b3ba1f2cca6ec0d73a18a548b7717ca8531.json'))
      prev_tx = Tx.from_json(fixtures_file('ce5fad9b4ef094d8f4937b0707edaf0a6e6ceeaf67d5edbfd51f660eac8f398b.json'))
      tx.verify_input_signature(1, prev_tx).should == true
    end

  end

end
