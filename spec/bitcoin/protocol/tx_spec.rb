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

  it '#normalized_hash' do
    tx = Tx.new( @payload[0] )
    tx.normalized_hash.size.should == 64
    tx.normalized_hash.should == "402e30100b6937cc13828ca096377c93afc0ff227ad2f249245e5b1db9123a39"

    new_tx = JSON.parse(tx.to_json)
    script =  Bitcoin::Script.from_string(new_tx['in'][0]['scriptSig'])
    script.chunks[0].bitcoin_pushdata = Bitcoin::Script::OP_PUSHDATA2
    script.chunks[0].bitcoin_pushdata_length = script.chunks[0].bytesize
    new_tx['in'][0]['scriptSig'] = script.to_string
    new_tx = Bitcoin::P::Tx.from_hash(new_tx)

    new_tx.hash.should != tx.hash
    new_tx.normalized_hash.size.should == 64
    new_tx.normalized_hash.should == "402e30100b6937cc13828ca096377c93afc0ff227ad2f249245e5b1db9123a39"
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

    # toshi format
    Tx.from_json(fixtures_file('rawtx-02-toshi.json')).to_payload.should == Tx.from_json(fixtures_file('rawtx-02.json')).to_payload
    Tx.from_json(fixtures_file('rawtx-03-toshi.json')).to_payload.should == Tx.from_json(fixtures_file('rawtx-03.json')).to_payload
    Tx.from_json(fixtures_file('coinbase-toshi.json')).to_payload.should == Tx.from_json(fixtures_file('coinbase.json')).to_payload
  end

  it 'Tx.binary_from_json' do
    Tx.binary_from_json( fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json') ).should ==
      fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin')
  end
  
  it 'compares arrays of bytes' do
    # This function is used in validating an ECDSA signature's S value
    c1 = []
    c2 = []
    Bitcoin::Script::compare_big_endian(c1, c2).should == 0
    
    c1 = [0]
    c2 = []
    Bitcoin::Script::compare_big_endian(c1, c2).should == 0
    
    c1 = []
    c2 = [0]
    Bitcoin::Script::compare_big_endian(c1, c2).should == 0
    
    c1 = [5]
    c2 = [5]
    Bitcoin::Script::compare_big_endian(c1, c2).should == 0
    
    c1 = [04]
    c2 = [5]
    Bitcoin::Script::compare_big_endian(c1, c2).should == -1
    
    c1 = [4]
    c2 = [05]
    Bitcoin::Script::compare_big_endian(c1, c2).should == -1
    
    c1 = [5]
    c2 = [4]
    Bitcoin::Script::compare_big_endian(c1, c2).should == 1
    
    c1 = [05]
    c2 = [004]
    Bitcoin::Script::compare_big_endian(c1, c2).should == 1

  end

  it 'validates ECDSA signature format' do
    # TX 3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae
    sig_orig = ["304502210088984573e3e4f33db7df6aea313f1ce67a3ef3532ea89991494c7f018258371802206ceefc9291450dbd40d834f249658e0f64662d52a41cf14e20c9781144f2fe0701"].pack("H*")
    Bitcoin::Script::is_der_signature?(sig_orig).should == true
    Bitcoin::Script::is_defined_hashtype_signature?(sig_orig).should == true

    # Trimmed to be too short
    sig = sig_orig.slice(0, 8)
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Zero-padded to be too long
    sig = String.new(sig_orig)
    sig << 0x00
    sig << 0x00
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Wrong first byte
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[0] = 0x20
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Length byte broken
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[1] = 0x20
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Incorrect R value type
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[2] = 0x03
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # R value length infeasibly long
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[3] = sig_orig.size - 4
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Negative R value
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[4] = 0x80 | sig_bytes[4]
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # R value excessively padded
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[5] = 0x00
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Incorrect S value type
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[37] = 0x03
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Zero S length
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[38] = 0x00
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false

    # Negative S value
    sig_bytes = sig_orig.unpack("C*")
    sig_bytes[39] = 0x80 | sig_bytes[39]
    sig = sig_bytes.pack("C*")
    Bitcoin::Script::is_der_signature?(sig).should == false
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

    # 0:1:01 <signature> 0:1:01 0:1:00 <pubkey> OP_SWAP OP_1ADD OP_CHECKMULTISIG
    tx = Bitcoin::P::Tx.from_json(fixtures_file('cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2.json'))
    tx.hash.should == "cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58.json'))
    outpoint_tx.hash.should == "514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58"
    tx.verify_input_signature(0, outpoint_tx).should == true

    # OP_CHECKSIG with OP_0 from mainnet a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954 output 0
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28.json'))
    tx.hash.should == "9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954.json'))
    outpoint_tx.hash.should == "a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954"
    tx.verify_input_signature(0, outpoint_tx).should == true

    # drop OP_CODESEPARATOR in subscript for signature_hash_for_input
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa.json'))
    tx.hash.should == "46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224.json'))
    outpoint_tx.hash.should == "bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224"
    tx.verify_input_signature(0, outpoint_tx).should == true

    # drop OP_CODESEPARATOR in subscript for signature_hash_for_input
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8.json'))
    tx.hash.should == "aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e.json'))
    outpoint_tx.hash.should == "326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e"
    tx.verify_input_signature(0, outpoint_tx).should == true

    # drop multisig OP_CODESEPARATOR in subscript for signature_hash_for_input
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190.json'))
    tx.hash.should == "6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944.json'))
    outpoint_tx.hash.should == "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944"
    tx.verify_input_signature(0, outpoint_tx).should == true

    # drop multisig OP_CODESEPARATOR in subscript for signature_hash_for_input when used in ScriptSig
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb.json'))
    tx.hash.should == "eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d.json'))
    outpoint_tx.hash.should == "b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d"
    tx.verify_input_signature(1, outpoint_tx).should == true

    # OP_DUP OP_HASH160
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f.json'))
    tx.hash.should == "5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9.json'))
    outpoint_tx.hash.should == "b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9"
    tx.verify_input_signature(0, outpoint_tx).should == true
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742.json'))
    outpoint_tx.hash.should == "ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742"
    tx.verify_input_signature(1, outpoint_tx).should == true

    # testnet3 e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009
    tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009.json'))
    tx.hash.should == "e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009"
    prev_txs = {}
    tx.in.map{|i| i.previous_output }.uniq.each{|i| prev_txs[i] = Bitcoin::P::Tx.from_json(fixtures_file("tx-#{i}.json")) }
    tx.in.each.with_index{|i,idx|
      tx.verify_input_signature(idx, prev_txs[i.previous_output]).should == true
    }

    # BIP62 rule #2 - spend transaction has operations in its signature
    tx = Tx.new( fixtures_file('rawtx-testnet-3bc52ac063291ad92d95ddda5fd776a342083b95607ad32ed8bc6f8f7d30449e.bin') )
    tx.hash.should == "3bc52ac063291ad92d95ddda5fd776a342083b95607ad32ed8bc6f8f7d30449e"
    outpoint_tx = Tx.new( fixtures_file('rawtx-testnet-04fdc38d6722ab4b12d79113fc4b2896bdcc5169710690ee4e78541b98e467b4.bin') )
    outpoint_tx.hash.should == "04fdc38d6722ab4b12d79113fc4b2896bdcc5169710690ee4e78541b98e467b4"
    tx.verify_input_signature(0, outpoint_tx, Time.now.to_i).should == true
    tx.verify_input_signature(0, outpoint_tx, Time.now.to_i, verify_sigpushonly: true).should == false

    # BIP62 rule #6 - spend transaction has an unused "0" on the signature stack
    tx = Tx.new( fixtures_file('rawtx-testnet-0b294c7d11dd21bcccb8393e6744fed7d4d1981a08c00e3e88838cc421f33c9f.bin') )
    tx.hash.should == "0b294c7d11dd21bcccb8393e6744fed7d4d1981a08c00e3e88838cc421f33c9f"
    outpoint_tx = Tx.new( fixtures_file('rawtx-testnet-f80acbd2f594d04ddb0e1cacba662132104909157dff526935a3c88abe9201a5.bin') )
    outpoint_tx.hash.should == "f80acbd2f594d04ddb0e1cacba662132104909157dff526935a3c88abe9201a5"
    tx.verify_input_signature(0, outpoint_tx, Time.now.to_i).should == true
    tx.verify_input_signature(0, outpoint_tx, Time.now.to_i, verify_cleanstack: true).should == false

    # Ensure BIP62 is applied to P2SH scripts
    tx = Bitcoin::P::Tx.from_json(fixtures_file('7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d.json'))
    tx.hash.should == "7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477.json'))
    outpoint_tx.hash.should == "3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477"
    tx.verify_input_signature(0, outpoint_tx).should == true
    tx.verify_input_signature(0, outpoint_tx, Time.now.to_i, verify_low_s: true).should == false

    # testnet3 P2SH check
    tx = Bitcoin::P::Tx.from_json(fixtures_file('156e6e1b84c5c3bd3a0927b25e4119fadce6e6d5186f363317511d1d680fae9a.json'))
    tx.hash.should == "156e6e1b84c5c3bd3a0927b25e4119fadce6e6d5186f363317511d1d680fae9a"
    outpoint_tx = Bitcoin::P::Tx.from_json(fixtures_file('8d0b238a06b5a70be75d543902d02d7a514d68d3252a949a513865ac3538874c.json'))
    outpoint_tx.hash.should == "8d0b238a06b5a70be75d543902d02d7a514d68d3252a949a513865ac3538874c"
    tx.verify_input_signature(0, outpoint_tx).should == true
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
  
  it "#legacy_sigops_count" do
    Tx.new(@payload[0]).legacy_sigops_count.should == 2
    Tx.new(@payload[1]).legacy_sigops_count.should == 2
    Tx.new(@payload[2]).legacy_sigops_count.should == 2
    
    # Test sig ops count in inputs too.
    tx = Tx.new
    txin = TxIn.new
    txin.script_sig = Bitcoin::Script.from_string("10 OP_CHECKMULTISIGVERIFY OP_CHECKSIGVERIFY").to_binary
    tx.add_in(txin)
    txout = TxOut.new
    txout.pk_script = Bitcoin::Script.from_string("5 OP_CHECKMULTISIG OP_CHECKSIG").to_binary
    tx.add_out(txout)
    tx.legacy_sigops_count.should == (20 + 1 + 20 + 1)
    
  end
  
  describe "Tx - is_final?" do
    it "should be final if lock_time == 0" do
      tx = Tx.new
      tx.lock_time = 0
      tx.is_final?(0,0).should == true
      
      # even if has non-final input:
      txin = TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.is_final?(0,0).should == true
    end
    
    it "should be final if lock_time is below block_height" do
      tx = Tx.new
      txin = TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.lock_time = 6543
      tx.is_final?(6000,0).should == false
      tx.is_final?(6543,0).should == false # when equal to block height, still not final
      tx.is_final?(6544,0).should == true
      tx.is_final?(9999,0).should == true
    end
    
    it "should be final if lock_time is below timestamp" do
      tx = Tx.new
      txin = TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      txin = TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD # when equal, interpreted as threshold
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD - 1).should == false
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD).should == false # when equal to timestamp, still not final
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 1).should == true
      
      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD + 666
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 1).should == false
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 666).should == false # when equal to timestamp, still not final
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 667).should == true
    end
    
    it "should be final if all inputs are finalized regardless of lock_time" do
      tx = Tx.new
      txin = TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      txin = TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      
      tx.lock_time = 6543
      tx.is_final?(6000,0).should == true
      tx.is_final?(6543,0).should == true
      tx.is_final?(6544,0).should == true
      tx.is_final?(9999,0).should == true
      
      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD - 1).should == true
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD).should == true
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 1).should == true
      
      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD + 666
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 1).should == true
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 666).should == true
      tx.is_final?(0,Bitcoin::LOCKTIME_THRESHOLD + 667).should == true
    end
    
  end

  it '#calculate_minimum_fee' do
    tx = Tx.new( fixtures_file('rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin') )
    tx.minimum_relay_fee.should == 0
    tx.minimum_block_fee.should == 0
    tx = Tx.from_json(fixtures_file('bc179baab547b7d7c1d5d8d6f8b0cc6318eaa4b0dd0a093ad6ac7f5a1cb6b3ba.json'))
    tx.minimum_relay_fee.should == 0
    tx.minimum_block_fee.should == 10_000
  end

  it '#calculate_minimum_fee for litecoin' do
    tx = Tx.from_json(fixtures_file('litecoin-tx-f5aa30f574e3b6f1a3d99c07a6356ba812aabb9661e1d5f71edff828cbd5c996.json'))
    tx.minimum_relay_fee.should == 0
    tx.minimum_block_fee.should == 30_000
    Bitcoin.network = :litecoin # change to litecoin
    tx.minimum_relay_fee.should == 0
    tx.minimum_block_fee.should == 5_900_000
  end

  it "should compare transactions" do
    tx1 = Tx.new( @payload[0] )
    tx2 = Tx.new( @payload[1] )
    (tx1 == Bitcoin::P::Tx.from_json(tx1.to_json)).should == true
    (tx1 == tx2).should == false
    (tx1 == nil).should == false
  end

  describe "Tx - BIP Scripts" do

    it "should do OP_CHECKMULTISIG" do
      # checkmultisig without checkhashverify
      tx = Tx.from_json(fixtures_file('23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63.json'))
      prev_tx = Tx.from_json(fixtures_file('60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1.json'))
      tx.verify_input_signature(0, prev_tx).should == true

      # p2sh + multisig transaction from mainnet
      tx      = Tx.from_json( fixtures_file('rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json') )
      prev_tx = Tx.from_json( fixtures_file("rawtx-de35d060663750b3975b7997bde7fb76307cec5b270d12fcd9c4ad98b279c28c.json") )
      tx.verify_input_signature(0, prev_tx).should == true

      # checkmultisig for testnet3 tx: 2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1 input index 1
      tx      = Tx.from_json( fixtures_file('tx-2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1.json') )
      prev_tx = Tx.from_json( fixtures_file("tx-19aa42fee0fa57c45d3b16488198b27caaacc4ff5794510d0c17f173f05587ff.json") )
      tx.verify_input_signature(1, prev_tx).should == true
    end

    it "should do P2SH with inner OP_CHECKMULTISIG (BIP 0016)" do
      tx = Tx.from_json(fixtures_file('3a17dace09ffb919ed627a93f1873220f4c975c1248558b18d16bce25d38c4b7.json'))
      prev_tx = Tx.from_json(fixtures_file('35e2001b428891fefa0bfb73167c7360669d3cbd7b3aa78e7cad125ddfc51131.json'))
      tx.verify_input_signature(0, prev_tx).should == true

      tx = Tx.from_json(fixtures_file('bd1715f1abfdc62bea3f605bdb461b3ba1f2cca6ec0d73a18a548b7717ca8531.json'))
      prev_tx = Tx.from_json(fixtures_file('ce5fad9b4ef094d8f4937b0707edaf0a6e6ceeaf67d5edbfd51f660eac8f398b.json'))
      tx.verify_input_signature(1, prev_tx).should == true

      # p2sh transaction with non-standard OP_CHECKMULTISIG inside found in testnet3 tx: d3d77d63709e47d9ef58f0b557800115a6b676c6a423012fbb96f45d8fcef830
      tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-d3d77d63709e47d9ef58f0b557800115a6b676c6a423012fbb96f45d8fcef830.json'))
      tx.hash.should == "d3d77d63709e47d9ef58f0b557800115a6b676c6a423012fbb96f45d8fcef830"
      prev_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-313897799b1e37e9ecae15010e56156dddde4e683c96b0e713af95272c38aee0.json'))
      prev_tx.hash.should == "313897799b1e37e9ecae15010e56156dddde4e683c96b0e713af95272c38aee0"
      tx.verify_input_signature(0, prev_tx).should == true
    end

    it "should do P2SH with inner OP_CHECKSIG" do
      # p2sh transaction with non-standard OP_CHECKSIG inside found in testnet3 tx: 3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae
      tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae.json'))
      tx.hash.should == "3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae"
      prev_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-44b833074e671120ba33106877b49e86ece510824b9af477a3853972bcd8d06a.json'))
      prev_tx.hash.should == "44b833074e671120ba33106877b49e86ece510824b9af477a3853972bcd8d06a"
      tx.verify_input_signature(0, prev_tx).should == true
    end

    it "should do OP_CHECKMULTISIG with OP_0 used as a pubkey" do
      tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-6606c366a487bff9e412d0b6c09c14916319932db5954bf5d8719f43f828a3ba.json'))
      tx.hash.should == "6606c366a487bff9e412d0b6c09c14916319932db5954bf5d8719f43f828a3ba"
      prev_tx = Bitcoin::P::Tx.from_json(fixtures_file('tx-4142ee4877eb116abf955a7ec6ef2dc38133b793df762b76d75e3d7d4d8badc9.json'))
      prev_tx.hash.should == "4142ee4877eb116abf955a7ec6ef2dc38133b793df762b76d75e3d7d4d8badc9"
      tx.verify_input_signature(0, prev_tx).should == true
    end

  end
  
end
