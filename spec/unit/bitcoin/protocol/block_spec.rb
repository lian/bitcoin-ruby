# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Protocol::Block do
  let(:blocks) do
    {
      # block 0:
      # 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
      '0' => fixtures_file('rawblock-0.bin'),
      # block 1:
      # 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
      '1' => fixtures_file('rawblock-1.bin'),
      # block 9:
      # 000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805
      '9' => fixtures_file('rawblock-9.bin'),
      # block 170:
      # 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
      '170' => fixtures_file('rawblock-170.bin'),
      # block 131025:
      # 00000000000007d938dbdd433c5ae12a782de74abf7f566518bc2b2d0a1df145
      '131025' => fixtures_file('rawblock-131025.bin'),
      # block 26478:
      # 000000000214a3f06ee99a033a7f2252762d6a18d27c3cd8c8fe2278190da9f3
      'testnet-26478' => fixtures_file('rawblock-testnet-26478.bin'),
      'testnet-265322' => fixtures_file('rawblock-testnet-265322.bin'),
      # block 1151351:
      # 000000000000031525003c4e061fd2e5ce5f4fda6121a836e66f70ec2df621de
      'testnet-1151351' => fixtures_file('rawblock-testnet-1151351.bin'),
      # block 100005:
      # 000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45
      'filtered-0' => fixtures_file('filteredblock-0.bin')
    }
  end
  let(:block) { Bitcoin::Protocol::Block.new(blocks['0']) }

  it '#new' do
    Bitcoin::Protocol::Block.new(nil)
    Bitcoin::Protocol::Block.new(blocks['0'])

    expect do
      Bitcoin::Protocol::Block.new(blocks['0'][0..20])
    end.to raise_error(TypeError, "can't convert nil into Integer")

    block = Bitcoin::Protocol::Block.new(nil)
    expect(block.parse_data(blocks['0'])).to be true
    expect(block.header_info[7]).to eq(215)
    expect(block.to_payload).to eq(blocks['0'])

    block = Bitcoin::Protocol::Block.new(nil)
    expect(block.parse_data(blocks['0'] + 'AAAA')).to eq('AAAA')
    expect(block.header_info[7]).to eq(215)
    expect(block.to_payload).to eq(blocks['0'])

    # parse block which includes segwit tx
    block = Bitcoin::Protocol::Block.new(blocks['testnet-1151351'])
    expect(block.mrkl_root)
      .to eq('e4bbfc681f2bf0ed5fe13a01f5f82bd1844d406fe793a7ec590151f4ea4060d5'.htb.reverse)
  end

  it '#hash' do
    expect(block.hash)
      .to eq('00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048')
  end

  it '#tx' do
    expect(block.tx.size).to eq(1)
    expect(block.tx[0].is_a?(Bitcoin::Protocol::Tx)).to be true
    expect(block.tx[0].hash)
      .to eq('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098')
  end

  it '#tx_hashes' do
    expect(block.tx_hashes)
      .to eq(['0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098'])
  end

  it '#to_hash' do
    expect(block.to_hash.keys)
      .to eq(%w[hash ver prev_block mrkl_root time bits nonce n_tx size tx mrkl_tree])
  end

  it '#to_json' do
    expect(block.to_json).to eq(fixtures_file('rawblock-0.json'))
    expect(Bitcoin::Protocol::Block.new(blocks['1']).to_json)
      .to eq(fixtures_file('rawblock-1.json'))
    expect(Bitcoin::Protocol::Block.new(blocks['131025']).to_json)
      .to eq(fixtures_file('rawblock-131025.json'))
    expect(Bitcoin::Protocol::Block.new(blocks['testnet-26478']).to_json)
      .to eq(fixtures_file('rawblock-testnet-26478.json'))
    expect(Bitcoin::Protocol::Block.from_json(block.to_json).tx[0].in[0].sequence)
      .to eq("\xff\xff\xff\xff")
  end

  it '#to_payload' do
    expect(block.to_payload).to eq(block.payload)
    expect(Bitcoin::Protocol::Block.new(block.to_payload).to_payload)
      .to eq(block.payload)
    expect(Bitcoin::Protocol::Block.new(blocks['1']).to_payload)
      .to eq(blocks['1'])
    expect(Bitcoin::Protocol::Block.new(blocks['131025']).to_payload)
      .to eq(blocks['131025'])
    expect(Bitcoin::Protocol::Block.new(blocks['testnet-26478']).to_payload)
      .to eq(blocks['testnet-26478'])
  end

  describe '.from_json' do
    it 'should load blocks from json' do
      block = Bitcoin::Protocol::Block.from_json(
        fixtures_file('rawblock-0.json')
      )
      expect(block.to_payload).to eq(blocks['0'])
      expect(block.tx[0].in[0].sequence).to eq("\xff\xff\xff\xff")
      expect(
        Bitcoin::Protocol::Block.from_json(
          fixtures_file('rawblock-1.json')
        ).to_payload
      ).to eq(blocks['1'])

      expect(
        Bitcoin::Protocol::Block.from_json(
          fixtures_file('rawblock-131025.json')
        ).to_payload
      ).to eq(blocks['131025'])

      expect(
        Bitcoin::Protocol::Block.from_json(
          fixtures_file('rawblock-testnet-26478.json')
        ).to_payload
      ).to eq(blocks['testnet-26478'])

      # testnet3 block
      # 0000000000ac85bb2530a05a4214a387e6be02b22d3348abc5e7a5d9c4ce8dab
      block_raw = fixtures_file(
        'block-testnet-0000000000ac85bb2530a05a4214a387e6be02b22d3348abc5e7a5d9c4ce8dab.bin'
      )
      expect(Bitcoin::Protocol::Block.new(block_raw).to_payload)
        .to eq(block_raw)
    end

    it 'should work with litecoin blocks' do
      Bitcoin.network = :litecoin # change to litecoin
      litecoin_block =
        'litecoin-genesis-block-12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2'
      expect(
        Bitcoin::Protocol::Block.from_json(
          fixtures_file("#{litecoin_block}.json")
        ).to_payload
      ).to eq(fixtures_file("#{litecoin_block}.bin"))

      json = Bitcoin::Protocol::Block.new(
        fixtures_file("#{litecoin_block}.bin")
      ).to_json
      expect(Bitcoin::Protocol::Block.from_json(json).to_payload)
        .to eq(fixtures_file("#{litecoin_block}.bin"))
      expect(Bitcoin::Protocol::Block.from_json(json).hash)
        .to eq(litecoin_block.split('-').last)

      litecoin_block =
        'litecoin-block-80ca095ed10b02e53d769eb6eaf92cd04e9e0759e5be4a8477b42911ba49c78f'
      expect(
        Bitcoin::Protocol::Block.from_json(
          fixtures_file("#{litecoin_block}.json")
        ).to_payload
      ).to eq(fixtures_file("#{litecoin_block}.bin"))

      json = Bitcoin::Protocol::Block.new(
        fixtures_file("#{litecoin_block}.bin")
      ).to_json
      expect(Bitcoin::Protocol::Block.from_json(json).to_payload)
        .to eq(fixtures_file("#{litecoin_block}.bin"))
      expect(Bitcoin::Protocol::Block.from_json(json).hash)
        .to eq(litecoin_block.split('-').last)
    end

    it 'should check block hash' do
      block = Bitcoin::Protocol::Block.from_json(
        fixtures_file('rawblock-0.json')
      )
      h = block.to_hash
      h['hash'][0] = '1'

      expect do
        Bitcoin::Protocol::Block.from_hash(h)
      end.to raise_error(
        RuntimeError,
        'Block hash mismatch! Claimed: 10000000839a8e6886ab5951d76f411475428a' \
        'fc90947ee320161bbf18eb6048, Actual: 00000000839a8e6886ab5951d76f4114' \
        '75428afc90947ee320161bbf18eb6048'
      )
    end

    it 'should check merkle tree' do
      block = Bitcoin::Protocol::Block.from_json(
        fixtures_file('rawblock-0.json')
      )
      h = block.to_hash
      h['tx'][0]['ver'] = 2
      h['tx'][0]['hash'] =
        '5ea04451af738d113f0ae8559225b7f893f186f099d88c72230a5e19c0bb830d'

      expect do
        Bitcoin::Protocol::Block.from_hash(h)
      end.to raise_error(RuntimeError, /Block merkle root mismatch/)
    end
  end

  #
  # following test cases are borrowed from
  # https://github.com/bitcoinj/bitcoinj/blob/master/core/src/test/java/org/bitcoinj/core/FilteredBlockAndPartialMerkleTreeTests.java
  #
  it 'filtered block parsing' do
    block = Bitcoin::Protocol::Block.new

    block.parse_data_from_io(blocks['filtered-0'], :filtered)

    expect(block.verify_mrkl_root).to be true
    expect(block.hash)
      .to eq('000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45')
    expect(block.tx_hashes)
      .to eq(['63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5'])
  end

  it '#header_to_json' do
    # rubocop:disable Layout/IndentHeredoc,Layout/ClosingHeredocIndentation
    json = <<-JSON.chomp
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
    # rubocop:enable Layout/IndentHeredoc,Layout/ClosingHeredocIndentation
    expect(block.header_to_json).to eq(json)
  end

  it '#verify_mrkl_root' do
    block0 = Bitcoin::Protocol::Block.from_json(
      fixtures_file('rawblock-0.json')
    )
    block1 = Bitcoin::Protocol::Block.from_json(
      fixtures_file('rawblock-1.json')
    )
    expect(block0.tx.size).to eq(1)
    expect(block0.verify_mrkl_root).to be true
    block0.tx << block.tx.last # test against CVE-2012-2459
    expect(block0.verify_mrkl_root).to be false
    block0.tx = block1.tx
    expect(block0.verify_mrkl_root).to be false
  end

  it '#bip34_block_height' do
    # block version 1
    block = Bitcoin::Protocol::Block.from_json(
      fixtures_file('rawblock-131025.json')
    )
    expect(block.ver).to eq(1)
    expect(block.bip34_block_height).to be_nil
    # block version 2 (introduced by BIP_0034)
    block = Bitcoin::Protocol::Block.from_json(
      fixtures_file(
        '000000000000056b1a3d84a1e2b33cde8915a4b61c0cae14fca6d3e1490b4f98.json'
      )
    )
    expect(block.ver).to eq(2)
    expect(block.bip34_block_height).to eq(197_657)
  end

  it 'should work with huge block version' do
    expect(Bitcoin::Protocol::Block.new(blocks['testnet-265322']).hash)
      .to eq('0000000000014b351588a177be099e39afd4962cd3d58e9ab5cbe45a9cf83c8a')
  end
end
