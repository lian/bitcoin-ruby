# frozen_string_literal: true

require 'pry'
require 'spec_helper'

describe Bitcoin do
  before { Bitcoin.network = :bitcoin }

  describe '.hash160' do
    it 'produces the expected public key hash' do
      # 65 bytes (8 bit version + 512 bits) pubkey in hex (130 bytes)
      pubkey = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f6' \
               '1deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b' \
               '6bf11d5f'

      expect(Bitcoin.hash160(pubkey))
        .to eq('62e907b15cbf27d5425399ebf6f0fb50ebb88f18')
    end
  end

  describe '.hash160_to_address' do
    let(:pubkey_hash) { '62e907b15cbf27d5425399ebf6f0fb50ebb88f18' }

    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'produces the expected address' do
        expect(Bitcoin.hash160_to_address(pubkey_hash))
          .to eq('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'produces the expected address' do
        expect(Bitcoin.hash160_to_address(pubkey_hash))
          .to eq('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
      end
    end
  end

  describe '.pubkey_to_address' do
    let(:compressed_pubkey) do
      '029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4'
    end
    let(:uncompressed_pubkey) do
      '049e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4b823' \
      '14814017e4e9b06a0fd8e01772bb410cb1c36cfc2d03079c315bc7494b86'
    end

    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'works for compressed pubkey' do
        expect(Bitcoin.pubkey_to_address(compressed_pubkey))
          .to eq('mu6vSuyvpVxvDAJyZczjxaU56pXLNBSf9C')
      end

      it 'works for uncompressed pubkey' do
        expect(Bitcoin.pubkey_to_address(uncompressed_pubkey))
          .to eq('n4bZ82i9SdLj6YauPn3PPKFRhQHMZrdaPq')
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'works for compressed pubkey' do
        expect(Bitcoin.pubkey_to_address(compressed_pubkey))
          .to eq('1Eay9rtx1UXfS3qMr42N8fFkEpvdR2euvg')
      end

      it 'works for uncompressed pubkey' do
        expect(Bitcoin.pubkey_to_address(uncompressed_pubkey))
          .to eq('1Q5bpydAdbuUKS7HgD51ZQ36qQgeiN8cBE')
      end
    end
  end

  describe '.pubkeys_to_p2sh_multisig_address' do
    let(:pubkey1) do
      '029e31ccb7308c2525d542024b8119a3ab3767933e82aedd1471f9c714d998d1b4'
    end
    let(:pubkey2) do
      '0299acf23a65c31fe02052d7474769529c21612b1afa56cc149747fe63867592ec'
    end
    let(:pubkey3) do
      '020b16a7227f873ac68cf3140f1101d2eda5acb28bf3e7d546409139caf25142e4'
    end

    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'produces the expected address and redeem script' do
        address, redeem_script = Bitcoin.pubkeys_to_p2sh_multisig_address(
          2, pubkey1, pubkey2
        )

        expect(address).to eq('2NGaiH7MNYWhsWPQKudZEvy8KnoWPfuGPg1')
        expect(redeem_script.hth)
          .to eq('52' + # OP_2
                 '21' + pubkey1 + # pubkey1.bytesize + pubkey1
                 '21' + pubkey2 + # pubkey2.bytesize + pubkey2
                 '52' + # OP_2
                 'ae') # OP_CHECKMULTISIG
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'produces the expected address and redeem script' do
        address, redeem_script = Bitcoin.pubkeys_to_p2sh_multisig_address(
          2, pubkey1, pubkey2, pubkey3
        )
        expect(address).to eq('38eiL6Jac27TVAu83wj81Miso9rXiVqgcP')
        expect(redeem_script.hth)
          .to eq('52' + # OP_2
                 '21' + pubkey1 + # pubkey1.bytesize + pubkey1
                 '21' + pubkey2 + # pubkey2.bytesize + pubkey2
                 '21' + pubkey3 + # pubkey3.bytesize + pubkey3
                 '53' + # OP_3
                 'ae') # OP_CHECKMULTISIG
      end
    end
  end

  describe '.hash160_from_address' do
    let(:pubkey_hash_hex) { '62e907b15cbf27d5425399ebf6f0fb50ebb88f18' }

    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'produces the expected hash' do
        expect(
          Bitcoin.hash160_from_address('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
        ).to eq('62e907b15cbf27d5425399ebf6f0fb50ebb88f18')
      end

      it 'returns nil for invalid address' do
        expect(Bitcoin.hash160_from_address('bad-address-testnet')).to be_nil
      end

      it 'survives rounds of conversion from hash160 to address' do
        addr = 'mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt'

        expect(
          Bitcoin.hash160_from_address(
            Bitcoin.hash160_to_address(pubkey_hash_hex)
          )
        ).to eq(pubkey_hash_hex)

        expect(
          Bitcoin.hash160_to_address(
            Bitcoin.hash160_from_address(addr)
          )
        ).to eq(addr)
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'returns expected values for addresses' do
        expect(
          Bitcoin.hash160_from_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
        ).to eq('62e907b15cbf27d5425399ebf6f0fb50ebb88f18')
        expect(
          Bitcoin.hash160_from_address('11ofrrzv87Ls97jN4TUetfQp4gEsUSL7A')
        ).to eq('0026f5494b39ea04b7bcb05e583acf3b0102d61f')
        expect(
          Bitcoin.hash160_from_address('11122RGUQSszAsTpptd2h8sdyYGR6nKs6f')
        ).to eq('0000daec8d6f05e949710f202c4f73258aa7791e')
        expect(
          Bitcoin.hash160_from_address('11119uLoMQCBHmKevdsFKHMaUoyrwLa9Y')
        ).to eq('00000090c66372823859c935149e2e32d276a1e6')
        expect(
          Bitcoin.hash160_from_address('1111136sgL8UNSTVL9ize2uGFPxFDGwFp')
        ).to eq('0000000096d3ad65d030a36e2c23f7fdd5dfcadb')
        expect(
          Bitcoin.hash160_from_address(
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
          )
        ).to eq('751e76e8199196d454941c45d1b3a323f1433bd6')
      end

      it 'returns nil for invalid address' do
        expect(Bitcoin.hash160_from_address('bad-address-mainnet')).to be_nil
      end

      it 'survives rounds of conversion from hash160 to address' do
        addr = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'

        expect(
          Bitcoin.hash160_from_address(
            Bitcoin.hash160_to_address(pubkey_hash_hex)
          )
        ).to eq(pubkey_hash_hex)

        expect(
          Bitcoin.hash160_to_address(
            Bitcoin.hash160_from_address(addr)
          )
        ).to eq(addr)
      end
    end
  end

  describe '.address_checksum?' do
    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'returns true for valid addresses' do
        expect(
          Bitcoin.address_checksum?('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
        ).to be true
        expect(
          Bitcoin.address_checksum?('1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW')
        ).to be true
      end

      it 'returns false for invalid addresses' do
        expect(Bitcoin.address_checksum?('f0f0f0')).to be false
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'returns true for valid addresses' do
        expect(
          Bitcoin.address_checksum?('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
        ).to be true
        expect(
          Bitcoin.address_checksum?('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
        ).to be true
      end

      it 'returns false for invalid addresses' do
        expect(Bitcoin.address_checksum?('f0f0f0')).to be false
      end
    end
  end

  describe '.valid_address?' do
    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'is true for valid addresses' do
        expect(
          Bitcoin.valid_address?('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
        ).to be true
      end

      it 'is false for invalid addresses' do
        expect(
          Bitcoin.valid_address?('1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW')
        ).to be false
        expect(
          Bitcoin.valid_address?('1moYFpRM4LkTV4Ho5eCxiEPB2bSm3AsJNGj')
        ).to be false
        expect(Bitcoin.valid_address?('f0f0f0')).to be false
      end

      it 'successfully validates a series of new addresses' do
        400.times do
          addr = Bitcoin.generate_address
          expect(Bitcoin.hash160_from_address(addr[0])).to eq(addr[-1])
          expect(Bitcoin.hash160_to_address(addr[-1])).to eq(addr[0])
          expect(Bitcoin.valid_address?(addr[0])).to be true
        end
      end

      it 'validates p2sh address' do
        expect(
          Bitcoin.valid_address?('2MyLngQnhzjzatKsB7XfHYoP9e2XUXSiBMM')
        ).to be true
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'is true for valid addresses' do
        expect(
          Bitcoin.valid_address?('1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW')
        ).to be true
        expect(
          Bitcoin.valid_address?('1ZQxJYBRmbb2rDNYPhd96x3eMbNnPD98q')
        ).to be true
        expect(
          Bitcoin.valid_address?('12KhCL8nGK3Luy7ehU3AxPs1mTocdessLM')
        ).to be true
        expect(
          Bitcoin.valid_address?('1AnNQgfaGgSKejzR6km74tyQPDGwZBBVT')
        ).to be true
      end

      it 'is false for invalid addresses' do
        expect(
          Bitcoin.valid_address?('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')
        ).to be false
        expect(
          Bitcoin.valid_address?('2D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW')
        ).to be false
        expect(
          Bitcoin.valid_address?('1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cX')
        ).to be false
        expect(
          Bitcoin.valid_address?('1moYFpRM4LkTV4Ho5eCxiEPB2bSm3AsJNGj')
        ).to be false
        expect(
          Bitcoin.valid_address?('f0f0f0')
        ).to be false
      end

      it 'successfully validates a series of new addresses' do
        400.times do
          addr = Bitcoin.generate_address
          expect(Bitcoin.hash160_from_address(addr[0])).to eq(addr[-1])
          expect(Bitcoin.hash160_to_address(addr[-1])).to eq(addr[0])
          expect(Bitcoin.valid_address?(addr[0])).to be true
        end
      end

      it 'validates p2sh address' do
        expect(
          Bitcoin.valid_address?('3CkxTG25waxsmd13FFgRChPuGYba3ar36B')
        ).to be true
      end
    end
  end

  describe '.base58_to_int' do
    it 'returns the expected integer equivalent' do
      expect(
        Bitcoin.base58_to_int('114EpVhtPpJQKti8HiH2fvXZFPiPkgDZrE')
      ).to eq(
        15_016_857_106_811_133_404_017_207_799_481_956_647_721_349_092_596_212_439
      )
    end
  end

  describe '.valid_pubkey?' do
    let(:key) { Bitcoin::Key.generate }

    it 'is true for compressed and uncompressed keys' do
      expect(Bitcoin.valid_pubkey?(key.pub_compressed)).to be true
      expect(Bitcoin.valid_pubkey?(key.pub_uncompressed)).to be true
    end

    it 'is false for invalid public keys' do
      expect(Bitcoin.valid_pubkey?(key.addr)).to be false
      expect(Bitcoin.valid_pubkey?(key.priv)).to be false
    end
  end

  describe '.address_type' do
    context 'testnet' do
      before { Bitcoin.network = :testnet }

      it 'works for a p2sh address' do
        expect(Bitcoin.address_type('2MyLngQnhzjzatKsB7XfHYoP9e2XUXSiBMM'))
          .to eq(:p2sh)
      end

      it 'works for a hash160 address' do
        expect(Bitcoin.address_type('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt'))
          .to eq(:hash160)
      end

      it 'is nil for an invalid address' do
        expect(Bitcoin.address_type('1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW'))
          .to be_nil
      end
    end

    context 'mainnet' do
      before { Bitcoin.network = :bitcoin }

      it 'works for a p2sh address' do
        expect(Bitcoin.address_type('3CkxTG25waxsmd13FFgRChPuGYba3ar36B'))
          .to eq(:p2sh)
      end

      it 'works for a hash160 address' do
        expect(Bitcoin.address_type('1D3KpY5kXnYhTbdCbZ9kXb2ZY7ZapD85cW'))
          .to eq(:hash160)
      end

      it 'works for a witness_v0_keyhash address' do
        expect(Bitcoin.address_type('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'))
          .to eq(:witness_v0_keyhash)
      end

      it 'works for a witness_v0_scripthash address' do
        expect(
          Bitcoin.address_type('bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3')
        ).to eq(:witness_v0_scripthash)
      end

      it 'is nil for invalid addresses' do
        expect(Bitcoin.address_type('bc1qw508d6qejxtdg4y5r3zarvayr0c5xw7kv8f3t4'))
          .to be_nil
        expect(Bitcoin.address_type('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt'))
          .to be_nil
      end
    end

    context 'litecoin' do
      before { Bitcoin.network = :litecoin }

      it 'works for p2sh addresses' do
        expect(
          Bitcoin.address_type('3CkxTG25waxsmd13FFgRChPuGYba3ar36B')
        ).to eq(:p2sh)
        expect(
          Bitcoin.address_type('MJy6m9S3thpJa8GwM8fm2LeJbFC22w18Vx')
        ).to eq(:p2sh)
      end

      it 'is nil for invalid addresses' do
        expect(
          Bitcoin.address_type('2MyLngQnhzjzatKsB7XfHYoP9e2XUXSiBMM')
        ).to be_nil
      end
    end

    context 'zcash' do
      before {
        Bitcoin::NETWORKS[:zcash] = Bitcoin::NETWORKS[:bitcoin].merge(
          project: :zcash,
          address_version: '1cb8',
          p2sh_version: '1cbd',
        )
        Bitcoin.network = :zcash
      }

      it 'works for a hash160 address' do
        expect(Bitcoin.address_type('t1KBT8oCGAfisNNWnSD3h7TSsZ7qKah935g'))
          .to eq(:hash160)
      end

      it 'is nil for invalid addresses' do
        expect(
          Bitcoin.address_type('2MyLngQnhzjzatKsB7XfHYoP9e2XUXSiBMM')
        ).to be_nil
      end
    end
  end

  describe '.checksum' do
    it 'produces the expected checksum' do
      expect(
        Bitcoin.checksum('0062e907b15cbf27d5425399ebf6f0fb50ebb88f18')
      ).to eq('c29b7d93')
    end
  end

  describe '.bitcoin_mrkl / .bitcoin_hash' do
    # block 170 is the first block that has a transaction.
    # hash 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
    let(:a) { 'b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082' }
    let(:b) { 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16' }
    let(:c) { '7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff' }

    it 'produces the expected values' do
      expect(Bitcoin.bitcoin_hash(b + a)).to eq(c)
      expect(Bitcoin.bitcoin_mrkl(a, b)).to eq(c)
    end
  end

  describe 'merkle trees' do
    let(:merkle_tree1) do
      # mrkl tree for block 170
      %w[
        b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082
        f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
        7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff
      ]
    end
    let(:merkle_tree2) do
      %w[
        4fa598026d9be1ca0c2bff1b531e566b7ea7f90b72e75fda0c1795bc2dfa375c
        186640daf908156e2616790d7c816235b0c43f668c3c38351b348c08ca44d457
        ef3928700309b4deceac9a992a19a7481b4e520cbc0b1ab74e2645eee39c8da0
        688c53517f62f7a65c0e87519c18a4de98f2ccafbf389b269d0bb867f88d166a
        01889506f7fe9210045f588361881e2d16a034a62bc48ebd7b6b0a3edeaf5a6d
        74f3a7df861d6a58957b84a3e425a8cf57e1e2e3a3def046dd200baeb8714f00
      ]
    end
    let(:merkle_tree3) do
      %w[
        349f717b6630e1f305f95964a2d94117dacca76e0b715d4d7a5657698ec96c6c
        7f44a84349200473455bcfc05ee68036e23993a6f58dce3f6a7faab46a754440
        6b3ba3fdfb7eeb6c2e5fd0e36e5bb4634da294521f7b1b808286c214981f9b17
        0467b41043d654ba3dc3940cbefec0eb38feed6e7085a8e825e4f782eccb48e3
        83d0231624f7a7d5c37557461ac0d09a8ad7a1f4ab673dd697acb275d4b114de
        074970aaa98db7d00e6f97a719fe85e9c7f51b75fa5a9a92218d568ccc2b21fe
        c1b6d2a416de6b63e42c1b50f229911bfb07f816e0795bb86ff7dcf0463ab0df
        751bcfd8acc10792f42050dca5b852f7a2fcd5300897d05907a98473f59a5650
        7abf551000d942efb93afc2d6174dc1bb7d41e8ea5fd76724685000734f1d77b
        e268927aa50d44de5365c11a2e402478767b7b98856a21a0715f9db65709aabb
        ed5ecc6b0e2fdd81be806599d6509d166e26849049e60e8d8b398641282b1e5a
        72e0e61880cc5fc9c7b5990c2d40b22eba783391b72807d2d5349fb55875c015
      ]
    end
    let(:merkle_tree4) do
      %w[
        627c859b5af6d537930fd16148eb0597542bea543f65fc2b0e5f188b5a458529
        d00b90525820a74f30ce26488db7f77c6ee9577e650568a051edd8560bbf83a1
        706b8ac1a433bc28385450626e12c1c7806032dc8b7e12221f417c5f22059d70
        10107ad569400a5f9621498e410845e6db0551671a2cafcf4358bd7867c6bc14
        ac6b08a363aedd5e58177c7f68bb213403ef78d24be0012c06b3483a9e2461fe
        d3074f5b33a44d9961f40eadf250cdc1425f7975012fccb6b06abc5202c53f4b
        3270c13599266d3a8da90a85a07fc003c58a8ff2938988356783b6261be335a6
        e097c3e2e3a07385628ac5a5a775e8a5e22dda3732bee32ae65b1430d080fc32
        c335a3963e8d89a9f46b94158d33f9b0dee25e776cba91be5eda44898bd31a78
        eb52315c6b26f72fa58ed95cd4886f1aa047ecd8f34ed8a367f59854f20733d8
        f97bf49e42e1732c0b515ecbac7cffc29c8c75c20c6783ad48b09d348fe0b6cf
        fc655dfc41eed4e2ea4cfe33ebb6bf593eb256bf86c17802fd03567668d0bf71
        06c4abf5dae15d5fa3632e7e5f82f05e7afbbfd495ea8015c6094764d868654c
        31bbd6e4523aeaaaf75b6ea4ef63d0fe3dba66fb719f4a4232891a3b58ad5cec
        0c728622b795e14ac40c4aa13cb732a0407b2b85c9108c6f06c083220bb6d65d
        f83f6ea46edcbeaa738ce4701bf48412a10c4b1a9f109efe44bc8fe5cb6b0017
        5e6168778c8407ace3ae9901a2f5197d6f21a6634ae0af639e52d14c39b13e02
        b92a7980b8a8a64f896027c0de732298d04ca56bea66c18cf97983037486e456
        2a2fd5e450b6ec31ccbe9d827f2e903714eb69c351300b1e76c587aef60e000c
        9ed561bb49c47648e0250cb074721d94cba84ed1e083f1e57c29eca78e36d73d
      ]
    end

    it 'produces the expected tree for a simple tree' do
      expect(Bitcoin.hash_mrkl_tree(merkle_tree1[0...2])).to eq(merkle_tree1)
    end

    it 'produces the expected tree for a larger tree' do
      expect(Bitcoin.hash_mrkl_tree(merkle_tree2[0...3])).to eq(merkle_tree2)

      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree2[0], merkle_tree2[1])
      ).to eq(merkle_tree2[3])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree2[2], merkle_tree2[2])
      ).to eq(merkle_tree2[4])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree2[3], merkle_tree2[4])
      ).to eq(merkle_tree2[5])

      merkle_tree2[0...3].each.with_index do |target, idx|
        branch = Bitcoin.hash_mrkl_branch(merkle_tree2[0...3], target)
        expect(
          Bitcoin.mrkl_branch_root(branch, target, idx)
        ).to eq(merkle_tree2[-1])
      end
    end

    it 'produces the expected results for a medium tree' do
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree3[0], merkle_tree3[1])
      ).to eq(merkle_tree3[6])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree3[2], merkle_tree3[3])
      ).to eq(merkle_tree3[7])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree3[4], merkle_tree3[5])
      ).to eq(merkle_tree3[8])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree3[6], merkle_tree3[7])
      ).to eq(merkle_tree3[9])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree3[8], merkle_tree3[8])
      ).to eq(merkle_tree3[10])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree3[9], merkle_tree3[10])
      ).to eq(merkle_tree3[11])
      expect(
        Bitcoin.hash_mrkl_tree(merkle_tree3[0...6])
      ).to eq(merkle_tree3)

      merkle_tree3[0...5].each.with_index do |target, idx|
        branch = Bitcoin.hash_mrkl_branch(merkle_tree3[0..5], target)
        expect(
          Bitcoin.mrkl_branch_root(branch, target, idx)
        ).to eq(merkle_tree3[-1])
      end
    end

    it 'produces the expected results for a very large tree' do
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[0], merkle_tree4[1])
      ).to eq(merkle_tree4[9])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[2], merkle_tree4[3])
      ).to eq(merkle_tree4[10])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[4], merkle_tree4[5])
      ).to eq(merkle_tree4[11])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[6], merkle_tree4[7])
      ).to eq(merkle_tree4[12])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[8], merkle_tree4[8])
      ).to eq(merkle_tree4[13])

      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[9], merkle_tree4[10])
      ).to eq(merkle_tree4[14])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[11], merkle_tree4[12])
      ).to eq(merkle_tree4[15])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[13], merkle_tree4[13])
      ).to eq(merkle_tree4[16])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[14], merkle_tree4[15])
      ).to eq(merkle_tree4[17])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[16], merkle_tree4[16])
      ).to eq(merkle_tree4[18])
      expect(
        Bitcoin.bitcoin_mrkl(merkle_tree4[17], merkle_tree4[18])
      ).to eq(merkle_tree4[19])

      expect(Bitcoin.hash_mrkl_tree(merkle_tree4[0...9])).to eq(merkle_tree4)

      merkle_tree4[0..8].each.with_index do |target, idx|
        branch = Bitcoin.hash_mrkl_branch(merkle_tree4[0..8], target)
        expect(
          Bitcoin.mrkl_branch_root(branch, target, idx)
        ).to eq(merkle_tree4[-1])
      end
    end

    it 'does not allow duplicate hash in merkle trees' do
      expect(
        Bitcoin.hash_mrkl_tree(%w[aa bb cc]).last
      ).not_to eq(Bitcoin.hash_mrkl_tree(%w[aa bb cc cc]).last)
    end

    it 'returns a value even if a merkle branch is empty' do
      branch = []
      mrkl_index = 0
      target = '089b911f5e471c0e1800f3384281ebec5b372fbb6f358790a92747ade271ccdf'
      expect(
        Bitcoin.mrkl_branch_root(branch.map(&:hth), target, mrkl_index)
      ).to eq(target)
    end
  end

  describe '.decode_compact_bits / .encode_compact_bits' do
    let(:target1) { 453_031_340 }
    let(:target2) { 486_604_799 }
    let(:target3) { 476_399_191 } # from block 40,320

    it 'decodes nonce compact bits to bignum hex' do
      expect(
        Bitcoin.decode_compact_bits(target1).index(/[^0]/)
      ).to eq(12)

      expect(
        Bitcoin.decode_compact_bits(target1).to_i(16)
      ).to eq(
        '000000000000b5ac000000000000000000000000000000000000000000000000'.to_i(16)
      )
      expect(
        Bitcoin.decode_compact_bits(target1)
      ).to eq('000000000000b5ac000000000000000000000000000000000000000000000000')
      expect(
        Bitcoin.decode_compact_bits(target2)
      ).to eq('00000000ffff0000000000000000000000000000000000000000000000000000')
      expect(
        Bitcoin.decode_compact_bits(target3)
      ).to eq('0000000065465700000000000000000000000000000000000000000000000000')

      # TODO: Remove this commented out test if it cannot be made to work.
      # Bitcoin.network = :dogecoin
      # expect(Bitcoin.decode_compact_bits('01fedcba'.to_i(16)).to_i(16)).to eq(-0x7e)
    end

    it 'encodes to the expected values' do
      expect(
        Bitcoin.encode_compact_bits(Bitcoin.decode_compact_bits(target1))
      ).to eq(target1)
      expect(
        Bitcoin.encode_compact_bits(Bitcoin.decode_compact_bits(target2))
      ).to eq(target2)
      expect(
        Bitcoin.encode_compact_bits(Bitcoin.decode_compact_bits(target3))
      ).to eq(target3)
    end
  end

  describe '.block_hash' do
    # Block #0, n_tx: 1
    let(:prev_block0) { '0000000000000000000000000000000000000000000000000000000000000000' }
    let(:merkle_root0) { '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b' }
    let(:time_bits_nonce_ver0) { [1_231_006_505, 486_604_799, 2_083_236_893, 1] }
    let(:expected_block_hash0) do
      '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    end

    # Block #1, n_tx: 1
    let(:prev_block1) { '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f' }
    let(:merkle_root1) { '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098' }
    let(:time_bits_nonce_ver1) { [1_231_469_665, 486_604_799, 2_573_394_689, 1] }
    let(:expected_block_hash1) do
      '00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048'
    end

    # Block #169, n_tx: 1
    let(:prev_block169) { '00000000567e95797f93675ac23683ae3787b183bb36859c18d9220f3fa66a69' }
    let(:merkle_root169) { 'd7b9a9da6becbf47494c27e913241e5a2b85c5cceba4b2f0d8305e0a87b92d98' }
    let(:time_bits_nonce_ver169) { [1_231_730_523, 486_604_799, 3_718_213_931, 1] }
    let(:expected_block_hash169) do
      '000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55'
    end

    # Block #171, n_tx: 1
    let(:prev_block171) { '00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee' }
    let(:merkle_root171) { 'd5f2d21453a6f0e67b5c42959c9700853e4c4d46fa7519d1cc58e77369c893f2' }
    let(:time_bits_nonce_ver171) { [1_231_731_401, 486_604_799, 653_436_935, 1] }
    let(:expected_block_hash171) do
      '00000000c9ec538cab7f38ef9c67a95742f56ab07b0a37c5be6b02808dbfb4e0'
    end

    it 'produces the expected block hash' do
      expect(
        Bitcoin.block_hash(prev_block0, merkle_root0, *time_bits_nonce_ver0)
      ).to eq(expected_block_hash0)
      expect(
        Bitcoin.block_hash(prev_block1, merkle_root1, *time_bits_nonce_ver1)
      ).to eq(expected_block_hash1)
      expect(
        Bitcoin.block_hash(prev_block169, merkle_root169, *time_bits_nonce_ver169)
      ).to eq(expected_block_hash169)
      expect(
        Bitcoin.block_hash(prev_block171, merkle_root171, *time_bits_nonce_ver171)
      ).to eq(expected_block_hash171)
    end
  end

  describe '.generate_key' do
    it 'generates an openssl-secp256k1 private/public keypair' do
      private_key, public_key = Bitcoin.generate_key

      expect(private_key.size).to eq(64) # bytes in hex
      expect(public_key.size).to eq(130) # bytes in hex

      key = Bitcoin.open_key(private_key, public_key)
      expect(Bitcoin.inspect_key(key)).to eq([private_key, public_key])
    end
  end

  describe 'Bitcoin::OpenSSL_EC' do
    it 'OpenSSL library is available' do
      expect do
        Bitcoin::OpenSSL_EC
      end.not_to raise_error
    end

    describe 'Bitcoin.open_key' do
      it 'opens key from private key and resolves public key' do
        50.times do
          private_key, public_key = Bitcoin.generate_key
          key = Bitcoin.open_key(private_key)

          expect(key.private_key_hex).to eq(private_key)
          expect(key.public_key_hex).to eq(public_key)
        end
      end
    end

    describe 'signing and verifying messages' do
      context 'testnet' do
        before { Bitcoin.network = :testnet3 }

        it 'verifies the signature of a testnet address' do
          expect(
            Bitcoin.verify_message(
              'mwPVMbZQgkpwJJt2YP3sLSgbEBQw3FWZSc',
              'H5GER0Nz+L7TPZMQzXtv0hnLSsyfPok9lkdHIv01vksREpEpOhTPTonU1xvy' \
              'PAOIIKhU3++Ol+LaWKWmsfyxDXk=',
              'A' * 500
            )
          ).to be true
        end
      end

      context 'mainnet' do
        before { Bitcoin.network = :bitcoin }
        let(:address_and_keys1) do
          %w[
            1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ
            12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747
            040b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a7 \
            447b5f0bba9e01e6fe4735c8383e6e7a3347a0fd72381b8f797a19f694054e5a69
          ]
        end
        let(:address_and_keys2) do
          %w[
            1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs
            12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747
            030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744
          ]
        end

        it 'successfully signs and verifies the message' do
          [address_and_keys1, address_and_keys2].each do |_addr, privkey, _pubkey|
            key = Bitcoin.open_key(privkey)
            16.times.each do |count|
              signature = Bitcoin.sign_message(
                key.private_key_hex,
                key.public_key_hex,
                format('Very secret message %<count>d: 11', count: count)
              )
              expect(
                Bitcoin.verify_message(
                  signature['address'],
                  'invalid-signature',
                  signature['message']
                )
              ).to be false
              expect(
                Bitcoin.verify_message(
                  signature['address'],
                  signature['signature'],
                  signature['message']
                )
              ).to be true
            end
          end
        end
      end
    end
  end

  describe '.generate_address' do
    it 'generates a new bitcoin address' do
      address, private_key, public_key, _hash160 = Bitcoin.generate_address

      expect(private_key.size).to eq(64) # bytes in hex
      expect(public_key.size).to eq(130) # bytes in hex
      expect(
        Bitcoin.hash160_to_address(Bitcoin.hash160(public_key))
      ).to eq(address)
    end
  end

  describe '.encode_base58 / decode_base58' do
    it 'passes tests from bitcoin core' do
      # fixtures from: https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp
      bin = [
        '',
        "\x61",
        "\x62\x62\x62",
        "\x63\x63\x63",
        "\x73\x69\x6d\x70\x6c\x79\x20\x61\x20\x6c\x6f\x6e\x67\x20\x73\x74\x72\x69\x6e\x67",
        "\x00\xeb\x15\x23\x1d\xfc\xeb\x60\x92\x58\x86\xb6\x7d\x06\x52\x99\x92" \
          "\x59\x15\xae\xb1\x72\xc0\x66\x47",
        "\x51\x6b\x6f\xcd\x0f",
        "\xbf\x4f\x89\x00\x1e\x67\x02\x74\xdd",
        "\x57\x2e\x47\x94",
        "\xec\xac\x89\xca\xd9\x39\x23\xc0\x23\x21",
        "\x10\xc8\x51\x1e",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      ]
      out = [
        '',
        '2g',
        'a3gV',
        'aPEr',
        '2cFupjhnEsSn59qHXstmK2ffpLv2',
        '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L',
        'ABnLTmg',
        '3SEo3LWLoPntC',
        '3EFU7m',
        'EJDM8drfXA6uyA',
        'Rt5zm',
        '1111111111'
      ]

      fixtures = bin.zip(out).map { |b, o| [b.unpack('H*')[0], o] }
      fixtures.each do |hex, output|
        expect(Bitcoin.encode_base58(hex)).to eq(output)
        expect(Bitcoin.decode_base58(output)).to eq(hex)
      end
    end
  end

  it '.block_next_retarget' do
    expect(Bitcoin.block_next_retarget(189_408)).to eq(189_503)
    expect(Bitcoin.block_next_retarget(189_503)).to eq(189_503)
    expect(Bitcoin.block_next_retarget(189_504)).to eq(191_519)
  end

  it '.block_difficulty' do
    expect(Bitcoin.block_difficulty(436_835_377)).to eq('1751454.5353407')
  end

  describe '.block_new_target' do
    before { Bitcoin.network = :bitcoin }

    it 'should calculate retarget difficulty' do
      prev_height = 201_599
      prev_block_time = 1_349_227_021
      prev_block_bits = 0x1a05db8b
      last_retarget_time = 1_348_092_851
      new_difficulty = Bitcoin.block_new_target(
        prev_height, prev_block_time, prev_block_bits, last_retarget_time
      )

      expect(
        Bitcoin.decode_compact_bits(new_difficulty)
      ).to eq(Bitcoin.decode_compact_bits(0x1a057e08))
    end
  end

  it '.block_hashes_to_win' do
    expect(Bitcoin.block_hashes_to_win(436_835_377))
      .to eq(7_522_554_734_795_001)
  end

  it '.block_probability' do
    expect(Bitcoin.block_probability(436_835_377))
      .to eq('0.0000000000000001329335625003267087884673003372881794348')
  end

  it '.block_average_hashing_time' do
    expect(
      Bitcoin.block_average_hashing_time(436_835_377, 630_000_000)
    ).to eq(11_940_563)
  end

  it '.block_average_mining_time' do
    expect(
      Bitcoin.block_average_mining_time(0x1a022fbe, 231_337, 270.0, 1.0)
    ).to eq(56.50855038530773) # days
  end

  it '.blockchain_total_btc' do
    block_heights = [0, 209_999, 210_000, 419_999, 420_000, 1_680_000]
    expected_results = [
      [5_000_000_000, 1, 5_000_000_000, 0],
      [1_050_000_000_000_000, 1, 5_000_000_000, 209_999],
      [1_050_005_000_000_000, 2, 2_500_000_000, 210_000],
      [1_575_002_500_000_000, 2, 2_500_000_000, 419_999],
      [1_575_005_000_000_000, 3, 1_250_000_000, 4_200_00],
      [2_091_801_875_000_000, 9, 19_531_250, 1_680_000]
    ]

    block_heights.zip(expected_results).map do |height, expected_result|
      expect(Bitcoin.blockchain_total_btc(height)).to eq(expected_result)
    end
  end

  it '.block_creation_reward' do
    heights = [0, 209_999, 210_000, 419_999, 420_000, 1_680_000]
    rewards = [
      5_000_000_000,
      5_000_000_000,
      2_500_000_000,
      2_500_000_000,
      1_250_000_000,
      19_531_250
    ]

    heights.zip(rewards).map do |height, reward|
      expect(Bitcoin.block_creation_reward(height)).to eq(reward)
    end
  end

  describe 'bitcoin base58 test vectors' do
    # Port of Bitcoin Core test vectors.
    # https://github.com/bitcoin/bitcoin/blob/595a7bab23bc21049526229054ea1fff1a29c0bf/src/test/base58_tests.cpp#L139
    let(:valid_base58_keys) do
      JSON.parse(fixtures_file('base58_keys_valid.json'))
    end
    # Port of Bitcoin Core test vectors.
    # https://github.com/bitcoin/bitcoin/blob/595a7bab23bc21049526229054ea1fff1a29c0bf/src/test/base58_tests.cpp#L179
    let(:invalid_base58_keys) do
      JSON.parse(fixtures_file('base58_keys_invalid.json'))
    end

    it 'passes the valid keys cases' do
      valid_base58_keys.each do |test_case|
        # NOTE: Single element arrays in tests are comments
        next if test_case.length == 1

        address = test_case[0]
        script = test_case[1].htb
        is_privkey = test_case[2].fetch('isPrivkey')
        is_swapcase_valid = test_case[2].fetch('tryCaseFlip', false)

        Bitcoin.network =
          case test_case[2].fetch('chain').to_sym
          when :main then :bitcoin
          when :test then :testnet3
          when :regtest then :regtest
          end

        # This spec only tests address generation, not base58 private key encoding
        next if is_privkey

        computed_script = Bitcoin::Script.to_address_script(address)
        expect(computed_script).to eq(script)

        expect(Bitcoin.valid_address?(address.swapcase)).to eq(is_swapcase_valid)

        computed_address = Bitcoin::Script.new(script).get_address
        expect(computed_address).to eq(address)
      end
    end

    it 'fails the invalid keys cases' do
      test_cases = JSON.parse(fixtures_file('base58_keys_invalid.json'))
      test_cases.each do |test_case|
        address = test_case[0]

        %i[bitcoin testnet3 regtest].each do |network_name|
          Bitcoin.network = network_name
          expect(Bitcoin.valid_address?(address)).to be false
        end
      end
    end
  end

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
      expect(Digest::SHA256.hexdigest('hello'))
        .to eq('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')

      # second round sha256
      expect(
        Digest::SHA256.hexdigest(Digest::SHA256.digest('hello'))
      ).to eq('9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50')
    end

    it 'RIPEMD-160 encoding of string "hello"' do
      # first round sha256
      expect(Digest::SHA256.hexdigest('hello'))
        .to eq('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')

      # second round rmd160
      expect(
        Digest::RMD160.hexdigest(Digest::SHA256.digest('hello'))
      ).to eq('b6a9c8c230722b7c748331a8b450f05566dc7d0f')
    end
  end
end
