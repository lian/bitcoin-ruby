# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'bitcoin'


describe 'Bitcoin Address/Hash160/PubKey' do

  it 'bitcoin-hash160 from public key' do
    # 65 bytes (8 bit version + 512 bits) pubkey in hex (130 bytes)
    pubkey = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    Bitcoin.hash160(pubkey).should == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"
  end

  it 'bitcoin-address from bitcoin-hash160' do
    # 20 bytes (160 bit) hash160 in hex (40 bytes)

    Bitcoin::network = :testnet
    Bitcoin.hash160_to_address("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
      .should == "mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt"

    Bitcoin::network = :bitcoin
    Bitcoin.hash160_to_address("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")
      .should == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
  end

  it 'bitcoin-address from pubkey' do
    Bitcoin::network = :testnet
    Bitcoin.pubkey_to_address("029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4")
      .should == "mu6vSuyvpVxvDAJyZczjxaU56pXLNBSf9C"
    Bitcoin.pubkey_to_address("049e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4b82314814017e4e9b06a0fd8e01772bb410cb1c36cfc2d03079c315bc7494b86")
    .should == "n4bZ82i9SdLj6YauPn3PPKFRhQHMZrdaPq"

    Bitcoin::network = :bitcoin
    Bitcoin.pubkey_to_address("029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4")
    .should == "1Eay9rtx1UXfS3qMr42N8fFkEpvdR2euvg"
    Bitcoin.pubkey_to_address("049e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4b82314814017e4e9b06a0fd8e01772bb410cb1c36cfc2d03079c315bc7494b86")
    .should == "1Q5bpydAdbuUKS7HgD51ZQ36qQgeiN8cBE"
  end

  it 'bitcoin p2sh multisig address from pubkeys' do
    Bitcoin::network = :testnet
    address, redeem_script = Bitcoin.pubkeys_to_p2sh_multisig_address(2, "029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4",
                                                                      "0299acf23a65c31fe02052d7474769529c21612b1afa56cc149747fe63867592ec")
    address.should == "2NGaiH7MNYWhsWPQKudZEvy8KnoWPfuGPg1"
    redeem_script.hth.should == "52" + # OP_2
                                "21" + "029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4" + # pubkey.bytesize + pubkey
                                "21" + "0299acf23a65c31fe02052d7474769529c21612b1afa56cc149747fe63867592ec" + # pubkey.bytesize + pubkey
                                "52" +  # OP_2
                                "ae"    # OP_CHECKMULTISIG

    Bitcoin::network = :bitcoin
    address, redeem_script = Bitcoin.pubkeys_to_p2sh_multisig_address(2, "029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4",
                                                                      "0299acf23a65c31fe02052d7474769529c21612b1afa56cc149747fe63867592ec",
                                                                      "020b16a7227f873ac68cf3140f1101d2eda5acb28bf3e7d546409139caf25142e4")
    address.should == "38eiL6Jac27TVAu83wj81Miso9rXiVqgcP"
    redeem_script.hth.should == "52" + # OP_2
                                "21" + "029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4" + # pubkey.bytesize + pubkey
                                "21" + "0299acf23a65c31fe02052d7474769529c21612b1afa56cc149747fe63867592ec" + # pubkey.bytesize + pubkey
                                "21" + "020b16a7227f873ac68cf3140f1101d2eda5acb28bf3e7d546409139caf25142e4" + # pubkey.bytesize + pubkey
                                "53" +  # OP_3
                                "ae"    # OP_CHECKMULTISIG
  end

  it 'bitcoin p2sh address from bitcoin-hash160' do
    Bitcoin::network = :testnet
    Bitcoin.hash160_to_p2sh_address("d11e2f2f385efeecd30f867f1d55c0bc8a27f29e")
      .should == "2NCJwNct2SVE5VwdrPXmnek59kCfdgCpxeF"

    Bitcoin::network = :bitcoin
    Bitcoin.hash160_to_p2sh_address("d11e2f2f385efeecd30f867f1d55c0bc8a27f29e")
      .should == "3LkjJswzq2ijJA1JiQ9v2o5tXrTTvPtAMe"
  end

  it 'bitcoin-hash160 from bitcoin-address' do
    Bitcoin::network = :testnet
    Bitcoin.hash160_from_address("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt")
      .should == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"
    Bitcoin.hash160_from_address("totally-invalid").should == nil

    Bitcoin::network = :bitcoin
    Bitcoin.hash160_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
      .should == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"

    Bitcoin.hash160_from_address("11ofrrzv87Ls97jN4TUetfQp4gEsUSL7A")
      .should == "0026f5494b39ea04b7bcb05e583acf3b0102d61f"
    Bitcoin.hash160_from_address("11122RGUQSszAsTpptd2h8sdyYGR6nKs6f")
      .should == "0000daec8d6f05e949710f202c4f73258aa7791e"
    Bitcoin.hash160_from_address("11119uLoMQCBHmKevdsFKHMaUoyrwLa9Y")
      .should == "00000090c66372823859c935149e2e32d276a1e6"
    Bitcoin.hash160_from_address("1111136sgL8UNSTVL9ize2uGFPxFDGwFp")
      .should == "0000000096d3ad65d030a36e2c23f7fdd5dfcadb"
  end

  it 'should survive rounds of hash160 <-> address' do
    hex = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"

    Bitcoin::network = :testnet
    addr = "mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt"
    Bitcoin.hash160_from_address(Bitcoin.hash160_to_address(hex)).should == hex
    Bitcoin.hash160_to_address(Bitcoin.hash160_from_address(addr)).should == addr

    Bitcoin::network = :bitcoin
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    Bitcoin.hash160_from_address(Bitcoin.hash160_to_address(hex)).should == hex
    Bitcoin.hash160_to_address(Bitcoin.hash160_from_address(addr)).should == addr
  end

  it '#address_checksum?' do
    Bitcoin::network = :testnet
    Bitcoin.address_checksum?("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").should == true
    Bitcoin.address_checksum?("1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW").should == true
    Bitcoin.address_checksum?("f0f0f0").should == false

    Bitcoin::network = :bitcoin
    Bitcoin.address_checksum?("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").should == true
    Bitcoin.address_checksum?("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").should == true
    Bitcoin.address_checksum?("f0f0f0").should == false
  end

  it 'validate bitcoin-address' do

    Bitcoin::network = :testnet

    Bitcoin.valid_address?("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").should == true
    Bitcoin.valid_address?("1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW").should == false
    Bitcoin.valid_address?("1moYFpRM4LkTV4Ho5eCxiEPB2bSm3AsJNGj").should == false
    Bitcoin.valid_address?("f0f0f0").should == false

    Bitcoin::network = :bitcoin

    Bitcoin.valid_address?("1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW").should == true
    Bitcoin.valid_address?("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").should == false
    Bitcoin.valid_address?("2D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW").should == false
    Bitcoin.valid_address?("1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cX").should == false
    Bitcoin.valid_address?("1moYFpRM4LkTV4Ho5eCxiEPB2bSm3AsJNGj").should == false

    Bitcoin.valid_address?("1ZQxJYBRmbb2rDNYPhd96x3eMbNnPD98q").should == true
    Bitcoin.valid_address?("12KhCL8nGK3Luy7ehU3AxPs1mTocdessLM").should == true
    Bitcoin.valid_address?("1AnNQgfaGgSKejzR6km74tyQPDGwZBBVT").should == true
    Bitcoin.valid_address?("f0f0f0").should == false


    Bitcoin.base58_to_int("114EpVhtPpJQKti8HiH2fvXZFPiPkgDZrE").should \
      == 15016857106811133404017207799481956647721349092596212439

    Bitcoin.network, success = :testnet, true
    400.times{
      addr = Bitcoin.generate_address
      success = false if Bitcoin.hash160_from_address(addr[0])  != addr[-1]
      success = false if Bitcoin.hash160_to_address(addr[-1])   != addr[0]
      success = false if Bitcoin.valid_address?(addr[0]) != true
    }
    success.should == true

    Bitcoin.network, success = :bitcoin, true
    400.times{
      addr = Bitcoin.generate_address
      success = false if Bitcoin.hash160_from_address(addr[0]) != addr[-1]
      success = false if Bitcoin.hash160_to_address(addr[-1])  != addr[0]
      success = false if Bitcoin.valid_address?(addr[0]) != true
    }
    success.should == true
  end

  it 'validate bitcoin public key' do
    key = Bitcoin::Key.generate
    Bitcoin.valid_pubkey?(key.pub_compressed).should == true
    Bitcoin.valid_pubkey?(key.pub_uncompressed).should == true
    Bitcoin.valid_pubkey?(key.addr).should == false
    Bitcoin.valid_pubkey?(key.priv).should == false
  end

  it 'validate p2sh address' do
    Bitcoin.network = :testnet
    Bitcoin.valid_address?("2MyLngQnhzjzatKsB7XfHYoP9e2XUXSiBMM").should == true
    Bitcoin.network = :bitcoin
    Bitcoin.valid_address?("3CkxTG25waxsmd13FFgRChPuGYba3ar36B").should == true
  end

  it '#address_type' do
    Bitcoin.network = :testnet
    Bitcoin.address_type("2MyLngQnhzjzatKsB7XfHYoP9e2XUXSiBMM").should == :p2sh
    Bitcoin.address_type("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").should == :hash160
    Bitcoin.address_type("1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW").should == nil
    Bitcoin.network = :bitcoin
    Bitcoin.address_type("3CkxTG25waxsmd13FFgRChPuGYba3ar36B").should == :p2sh
    Bitcoin.address_type("1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW").should == :hash160
    Bitcoin.address_type("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").should == nil
  end

  it 'Bitcoin#checksum' do
    Bitcoin.checksum("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18").should == "c29b7d93"
  end

  it '#bitcoin_mrkl' do
    # block 170 is the first block that has a transaction.
    # hash 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
    a = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082"
    b = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    c = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"

    Bitcoin.bitcoin_hash(b + a)    .should == c
    Bitcoin.bitcoin_mrkl(a , b)    .should == c
  end

  it 'mrkl_tree from transaction-hashes' do

    # mrkl tree for block 170
    mrkl_tree = [
      "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082",# tx 1
      "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",# tx 2
      "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
    ]
    Bitcoin.hash_mrkl_tree(mrkl_tree[0...2]).should == mrkl_tree


    mrkl_tree = [
      "4fa598026d9be1ca0c2bff1b531e566b7ea7f90b72e75fda0c1795bc2dfa375c",
      "186640daf908156e2616790d7c816235b0c43f668c3c38351b348c08ca44d457",
      "ef3928700309b4deceac9a992a19a7481b4e520cbc0b1ab74e2645eee39c8da0",

      "688c53517f62f7a65c0e87519c18a4de98f2ccafbf389b269d0bb867f88d166a",
      "01889506f7fe9210045f588361881e2d16a034a62bc48ebd7b6b0a3edeaf5a6d",

      "74f3a7df861d6a58957b84a3e425a8cf57e1e2e3a3def046dd200baeb8714f00"
    ]

    Bitcoin.hash_mrkl_tree( mrkl_tree[0...3] ).should == mrkl_tree

    Bitcoin.bitcoin_mrkl( mrkl_tree[0], mrkl_tree[1] ).should == mrkl_tree[3]
    Bitcoin.bitcoin_mrkl( mrkl_tree[2], mrkl_tree[2] ).should == mrkl_tree[4]
    Bitcoin.bitcoin_mrkl( mrkl_tree[3], mrkl_tree[4] ).should == mrkl_tree[5]

    mrkl_tree[0...3].each.with_index do |target, idx|
      branch = Bitcoin.hash_mrkl_branch( mrkl_tree[0...3], target )
      Bitcoin.mrkl_branch_root( branch, target, idx ).should == mrkl_tree[-1]
    end

    mrkl_tree = [
      "349f717b6630e1f305f95964a2d94117dacca76e0b715d4d7a5657698ec96c6c", # 0
      "7f44a84349200473455bcfc05ee68036e23993a6f58dce3f6a7faab46a754440", # 1
      "6b3ba3fdfb7eeb6c2e5fd0e36e5bb4634da294521f7b1b808286c214981f9b17", # 2
      "0467b41043d654ba3dc3940cbefec0eb38feed6e7085a8e825e4f782eccb48e3", # 3
      "83d0231624f7a7d5c37557461ac0d09a8ad7a1f4ab673dd697acb275d4b114de", # 4
      "074970aaa98db7d00e6f97a719fe85e9c7f51b75fa5a9a92218d568ccc2b21fe", # 5

      "c1b6d2a416de6b63e42c1b50f229911bfb07f816e0795bb86ff7dcf0463ab0df", # 6
      "751bcfd8acc10792f42050dca5b852f7a2fcd5300897d05907a98473f59a5650", # 7
      "7abf551000d942efb93afc2d6174dc1bb7d41e8ea5fd76724685000734f1d77b", # 8

      "e268927aa50d44de5365c11a2e402478767b7b98856a21a0715f9db65709aabb", # 9
      "ed5ecc6b0e2fdd81be806599d6509d166e26849049e60e8d8b398641282b1e5a", # 10

      "72e0e61880cc5fc9c7b5990c2d40b22eba783391b72807d2d5349fb55875c015"  # 11
    ]

    Bitcoin.bitcoin_mrkl( mrkl_tree[0], mrkl_tree[1] ).should == mrkl_tree[6]
    Bitcoin.bitcoin_mrkl( mrkl_tree[2], mrkl_tree[3] ).should == mrkl_tree[7]
    Bitcoin.bitcoin_mrkl( mrkl_tree[4], mrkl_tree[5] ).should == mrkl_tree[8]

    Bitcoin.bitcoin_mrkl( mrkl_tree[6], mrkl_tree[7] ).should == mrkl_tree[9]
    Bitcoin.bitcoin_mrkl( mrkl_tree[8], mrkl_tree[8] ).should == mrkl_tree[10]

    Bitcoin.bitcoin_mrkl( mrkl_tree[9], mrkl_tree[10] ).should == mrkl_tree[11]

    Bitcoin.hash_mrkl_tree(mrkl_tree[0...6]).should == mrkl_tree

    mrkl_tree[0...5].each.with_index do |target, idx|
      branch = Bitcoin.hash_mrkl_branch( mrkl_tree[0..5], target )
      Bitcoin.mrkl_branch_root( branch, target, idx ).should == mrkl_tree[-1]
    end

    mrkl_tree = [
      "627c859b5af6d537930fd16148eb0597542bea543f65fc2b0e5f188b5a458529", # 0
      "d00b90525820a74f30ce26488db7f77c6ee9577e650568a051edd8560bbf83a1", # 1
      "706b8ac1a433bc28385450626e12c1c7806032dc8b7e12221f417c5f22059d70", # 2
      "10107ad569400a5f9621498e410845e6db0551671a2cafcf4358bd7867c6bc14", # 3
      "ac6b08a363aedd5e58177c7f68bb213403ef78d24be0012c06b3483a9e2461fe", # 4
      "d3074f5b33a44d9961f40eadf250cdc1425f7975012fccb6b06abc5202c53f4b", # 5
      "3270c13599266d3a8da90a85a07fc003c58a8ff2938988356783b6261be335a6", # 6
      "e097c3e2e3a07385628ac5a5a775e8a5e22dda3732bee32ae65b1430d080fc32", # 7
      "c335a3963e8d89a9f46b94158d33f9b0dee25e776cba91be5eda44898bd31a78", # 8

      "eb52315c6b26f72fa58ed95cd4886f1aa047ecd8f34ed8a367f59854f20733d8", # 9
      "f97bf49e42e1732c0b515ecbac7cffc29c8c75c20c6783ad48b09d348fe0b6cf", # 10
      "fc655dfc41eed4e2ea4cfe33ebb6bf593eb256bf86c17802fd03567668d0bf71", # 11
      "06c4abf5dae15d5fa3632e7e5f82f05e7afbbfd495ea8015c6094764d868654c", # 12
      "31bbd6e4523aeaaaf75b6ea4ef63d0fe3dba66fb719f4a4232891a3b58ad5cec", # 13

      "0c728622b795e14ac40c4aa13cb732a0407b2b85c9108c6f06c083220bb6d65d", # 14
      "f83f6ea46edcbeaa738ce4701bf48412a10c4b1a9f109efe44bc8fe5cb6b0017", # 15
      "5e6168778c8407ace3ae9901a2f5197d6f21a6634ae0af639e52d14c39b13e02", # 16

      "b92a7980b8a8a64f896027c0de732298d04ca56bea66c18cf97983037486e456", # 17
      "2a2fd5e450b6ec31ccbe9d827f2e903714eb69c351300b1e76c587aef60e000c", # 18

      "9ed561bb49c47648e0250cb074721d94cba84ed1e083f1e57c29eca78e36d73d"  # 19
    ]

    Bitcoin.bitcoin_mrkl( mrkl_tree[0], mrkl_tree[1] ).should == mrkl_tree[9]
    Bitcoin.bitcoin_mrkl( mrkl_tree[2], mrkl_tree[3] ).should == mrkl_tree[10]
    Bitcoin.bitcoin_mrkl( mrkl_tree[4], mrkl_tree[5] ).should == mrkl_tree[11]
    Bitcoin.bitcoin_mrkl( mrkl_tree[6], mrkl_tree[7] ).should == mrkl_tree[12]
    Bitcoin.bitcoin_mrkl( mrkl_tree[8], mrkl_tree[8] ).should == mrkl_tree[13]

    Bitcoin.bitcoin_mrkl( mrkl_tree[9], mrkl_tree[10] ).should == mrkl_tree[14]
    Bitcoin.bitcoin_mrkl( mrkl_tree[11], mrkl_tree[12] ).should == mrkl_tree[15]
    Bitcoin.bitcoin_mrkl( mrkl_tree[13], mrkl_tree[13] ).should == mrkl_tree[16]

    Bitcoin.bitcoin_mrkl( mrkl_tree[14], mrkl_tree[15] ).should == mrkl_tree[17]
    Bitcoin.bitcoin_mrkl( mrkl_tree[16], mrkl_tree[16] ).should == mrkl_tree[18]

    Bitcoin.bitcoin_mrkl( mrkl_tree[17], mrkl_tree[18] ).should == mrkl_tree[19]

    Bitcoin.hash_mrkl_tree(mrkl_tree[0...9]).should == mrkl_tree

    mrkl_tree[0..8].each.with_index do |target, idx|
      branch = Bitcoin.hash_mrkl_branch( mrkl_tree[0..8], target )
      Bitcoin.mrkl_branch_root( branch, target, idx ).should == mrkl_tree[-1]
    end

  end

  it 'should not allow duplicate hash in merkle trees' do
    Bitcoin.hash_mrkl_tree(["aa", "bb", "cc"]).last.should !=
      Bitcoin.hash_mrkl_tree(["aa", "bb", "cc", "cc"]).last
  end
  
  it 'return a value even if a merkle branch is empty' do
    branch = []
    mrkl_index = 0
    target = "089b911f5e471c0e1800f3384281ebec5b372fbb6f358790a92747ade271ccdf"
    Bitcoin.mrkl_branch_root(branch.map(&:hth), target, mrkl_index).should == target
  end

  it 'nonce compact bits to bignum hex' do
    Bitcoin.decode_compact_bits( "1b00b5ac".to_i(16) ).index(/[^0]/).should == 12
    Bitcoin.decode_compact_bits( "1b00b5ac".to_i(16) ).to_i(16).should ==
      "000000000000b5ac000000000000000000000000000000000000000000000000".to_i(16)


    target = 453031340
    Bitcoin.decode_compact_bits( target ).should ==
      "000000000000b5ac000000000000000000000000000000000000000000000000"
    Bitcoin.encode_compact_bits( Bitcoin.decode_compact_bits( target ) ).should == target

    target = 486604799
    Bitcoin.decode_compact_bits( target ).should ==
      "00000000ffff0000000000000000000000000000000000000000000000000000"
    Bitcoin.encode_compact_bits( Bitcoin.decode_compact_bits( target ) ).should == target

    target = 476399191 # from block 40,320
    Bitcoin.decode_compact_bits(target).should ==
      "0000000065465700000000000000000000000000000000000000000000000000"
    Bitcoin.encode_compact_bits( Bitcoin.decode_compact_bits( target ) ).should == target

    #Bitcoin.network = :dogecoin
    #Bitcoin.decode_compact_bits( "01fedcba".to_i(16) ).to_i(16).should == -0x7e
  end

  it '#block_hash' do
    # block 0  n_tx: 1
    prev_block="0000000000000000000000000000000000000000000000000000000000000000"
    mrkl_root ="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    time, bits, nonce, ver = 1231006505, 486604799, 2083236893, 1

    Bitcoin.block_hash(prev_block, mrkl_root, time, bits, nonce, ver).should ==
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


    # block 1  n_tx: 1
    prev_block="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    mrkl_root ="0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    time, bits, nonce, ver = 1231469665, 486604799, 2573394689, 1

    Bitcoin.block_hash(prev_block, mrkl_root, time, bits, nonce, ver).should ==
      "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"

    #  .. only n_tx: 1

    # block 169  n_tx: 1
    prev_block="00000000567e95797f93675ac23683ae3787b183bb36859c18d9220f3fa66a69"
    mrkl_root ="d7b9a9da6becbf47494c27e913241e5a2b85c5cceba4b2f0d8305e0a87b92d98"
    time, bits, nonce, ver = 1231730523, 486604799, 3718213931, 1

    Bitcoin.block_hash(prev_block, mrkl_root, time, bits, nonce, ver).should ==
      "000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55"


    # block 170  n_tx: 2
    prev_block="000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55"
    mrkl_root ="7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
    time, bits, nonce, ver = 1231731025, 486604799, 1889418792, 1

    Bitcoin.block_hash(prev_block, mrkl_root, time, bits, nonce, ver).should ==
      "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"


    # block 171  n_tx: 1
    prev_block="00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"
    mrkl_root ="d5f2d21453a6f0e67b5c42959c9700853e4c4d46fa7519d1cc58e77369c893f2"
    time, bits, nonce, ver = 1231731401, 486604799, 653436935, 1
    Bitcoin.block_hash(prev_block, mrkl_root, time, bits, nonce, ver).should ==
      "00000000c9ec538cab7f38ef9c67a95742f56ab07b0a37c5be6b02808dbfb4e0"
  end

  it 'generates openssl-secp256k1 private/public keypair' do
    private_key, public_key = Bitcoin.generate_key

    private_key.size  .should == 64   # bytes in hex
    public_key.size   .should == 130  # bytes in hex

    key = Bitcoin.open_key(private_key, public_key)
    Bitcoin.inspect_key( key ).should == [ private_key, public_key ]
  end

  begin
    Bitcoin::OpenSSL_EC
    it 'opens key from private key and resolves public key' do
      50.times.all?{
        private_key, public_key = Bitcoin.generate_key
        key = Bitcoin.open_key(private_key)
        [ key.private_key_hex, key.public_key_hex ] == [ private_key, public_key ]
      }.should == true
    end

    it 'extract private key from uncompressed DER format' do
      der = "308201130201010420a29fe0f28b2936dbc89f889f74cd1f0662d18a873ac15d6cd417b808db1ccd0aa081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a14403420004768cfc6c44b927b0e69e9dd343e96132f7cd1d360d8cb8d65c83d89d7beaceadfd19918e076606a099344156acdb026b1065a958e39f098cfd0a34dd976291d6"

      Bitcoin::OpenSSL_EC.der_to_private_key(der).should == "a29fe0f28b2936dbc89f889f74cd1f0662d18a873ac15d6cd417b808db1ccd0a"
    end

    it 'sign and verify text messages (signmessage/verifymessage)' do
      [
        ["1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ", "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747",
         "040b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a7447b5f0bba9e01e6fe4735c8383e6e7a3347a0fd72381b8f797a19f694054e5a69"],
        ["1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs", "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747",
         "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744"]
      ].each{|address, privkey, pubkey|
        key = Bitcoin.open_key(privkey)
        16.times.all?{|n|
        #10_000.times.all?{|n|
        #  puts 'RAM USAGE: ' + `pmap #{Process.pid} | tail -1`[10,40].strip if (n % 1_000) == 0
          s = Bitcoin.sign_message(key.private_key_hex, key.public_key_hex, "Very secret message %d: 11" % n)
          Bitcoin.verify_message(s['address'], s['signature'], s['message'])
        }.should == true
      }
    end
  rescue LoadError
  end

  it 'generates new bitcoin-address' do
    address, private_key, public_key, hash160 = Bitcoin.generate_address

    private_key.size  .should == 64   # bytes in hex
    public_key.size   .should == 130  # bytes in hex
    #Bitcoin.valid_address?(address).should == true # fix/extend
    Bitcoin.hash160_to_address(Bitcoin.hash160(public_key)).should == address
  end

  it 'encodes and decodes base58' do
    # fixtures from: https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp
    bin = [
            "",
            "\x61",
            "\x62\x62\x62",
            "\x63\x63\x63",
            "\x73\x69\x6d\x70\x6c\x79\x20\x61\x20\x6c\x6f\x6e\x67\x20\x73\x74\x72\x69\x6e\x67",
            "\x00\xeb\x15\x23\x1d\xfc\xeb\x60\x92\x58\x86\xb6\x7d\x06\x52\x99\x92\x59\x15\xae\xb1\x72\xc0\x66\x47",
            "\x51\x6b\x6f\xcd\x0f",
            "\xbf\x4f\x89\x00\x1e\x67\x02\x74\xdd",
            "\x57\x2e\x47\x94",
            "\xec\xac\x89\xca\xd9\x39\x23\xc0\x23\x21",
            "\x10\xc8\x51\x1e",
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          ]
    out = [
            "",
            "2g",
            "a3gV",
            "aPEr",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
            "ABnLTmg",
            "3SEo3LWLoPntC",
            "3EFU7m",
            "EJDM8drfXA6uyA",
            "Rt5zm",
            "1111111111"
          ]

    fixtures = bin.zip(out).map{|b,out| [ b.unpack("H*")[0], out ] }
    #fixtures.each{|hex,out| p [hex, out, Bitcoin.encode_base58(hex), Bitcoin.decode_base58(out)] }
    fixtures.all?{|hex,out| Bitcoin.encode_base58(hex) == out }.should == true
    fixtures.all?{|hex,out| Bitcoin.decode_base58(out) == hex }.should == true
  end

  it '#block_next_retarget' do
    Bitcoin.block_next_retarget(189408).should == 189503
    Bitcoin.block_next_retarget(189503).should == 189503
    Bitcoin.block_next_retarget(189504).should == 191519
  end

  it '#block_difficulty' do
    Bitcoin.block_difficulty(436835377).should == "1751454.5353407"
  end

  it 'should calculate retarget difficulty' do
    prev_height = 201599
    prev_block_time = 1349227021
    prev_block_bits = 0x1a05db8b
    last_retarget_time = 1348092851
    new_difficulty = Bitcoin.block_new_target(prev_height, prev_block_time, prev_block_bits, last_retarget_time)
    
    Bitcoin.decode_compact_bits(new_difficulty.should) == Bitcoin.decode_compact_bits(0x1a057e08)
  end

  it '#block_hashes_to_win' do
    Bitcoin.block_hashes_to_win(436835377).should == 7522554734795001
  end

  it '#block_probability' do
    Bitcoin.block_probability(436835377).should ==
      "0.0000000000000001329335625003267087884673003372881794348"
  end

  it '#block_average_hashing_time' do
    Bitcoin.block_average_hashing_time(436835377, 630_000_000).should == 11940563
  end

  it '#block_average_mining_time' do
    Bitcoin.block_average_mining_time(0x1a022fbe, 231337, 270.0, 1.0).should == 56.50855038530773 # days
  end

  it '#blockchain_total_btc' do
    # 0.step(6930000, 210000){|height|
    #   p total_btc(height-1) unless height == 0
    #   p total_btc(height)
    # }
    [0, 209999, 210000, 419999, 420000, 1680000].map{|height|
      Bitcoin.blockchain_total_btc(height)
    }.should == [
      [5000000000,       1, 5000000000,       0],
      [1050000000000000, 1, 5000000000,  209999],
      [1050005000000000, 2, 2500000000,  210000],
      [1575002500000000, 2, 2500000000,  419999],
      [1575005000000000, 3, 1250000000,  420000],
      [2091801875000000, 9,   19531250, 1680000]
    ]
  end

  it '#block_creation_reward' do
    [0, 209999, 210000, 419999, 420000, 1680000].map{|height|
      Bitcoin.block_creation_reward(height)
    }.should == [ 5000000000, 5000000000, 2500000000, 2500000000, 1250000000, 19531250 ]
  end

end


__END__
describe 'Bitcoin-Wiki - Common Standards - Hashes' do
  # https://en.bitcoin.it/wiki/Protocol_specification
  # Hashes
  #  Usually, when a hash is computed within bitcoin, it is computed twice.
  #  Most of the time SHA-256 hashes are used, however RIPEMD-160 is also
  #  used when a shorter hash is desirable.

  require 'digest/sha2'
  require 'digest/rmd160'


  it 'double-SHA-256 encoding of string "hello"' do
     # first round sha256
     Digest::SHA256.hexdigest("hello").should ==
       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

     # second round sha256
     Digest::SHA256.hexdigest( Digest::SHA256.digest("hello") ).should ==
       "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
  end

  it 'RIPEMD-160 encoding of string "hello"' do
     # first round sha256
     Digest::SHA256.hexdigest("hello").should ==
       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

     # second round rmd160
     Digest::RMD160.hexdigest( Digest::SHA256.digest("hello") ).should ==
       "b6a9c8c230722b7c748331a8b450f05566dc7d0f"
  end
end
