# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Protocol::Tx do
  let(:payloads) do
    [
      fixtures_file('rawtx-01.bin'),
      fixtures_file('rawtx-02.bin'),
      fixtures_file('rawtx-03.bin'),
      fixtures_file('rawtx-p2wpkh.bin')
    ]
  end

  let(:json) do
    [
      fixtures_file('rawtx-01.json'),
      fixtures_file('rawtx-02.json'),
      fixtures_file('rawtx-03.json'),
      fixtures_file('rawtx-p2wpkh.json')
    ]
  end

  describe '#new' do
    it 'does not raise an error for valid payloads' do
      Bitcoin::Protocol::Tx.new(nil)
      payloads.each { |payload| Bitcoin::Protocol::Tx.new(payload) }
    end

    it 'raises an error for an invalid payload' do
      expect do
        Bitcoin::Protocol::Tx.new(payloads[0][0..20])
      end.to raise_error(NoMethodError, /undefined method `unpack'/)
    end

    it 'correctly deserializes a new, empty transaction' do
      Bitcoin::Protocol::Tx.new(Bitcoin::Protocol::Tx.new.to_payload)
    end
  end

  describe '#parse_data' do
    let(:tx) { Bitcoin::Protocol::Tx.new(nil) }

    it 'correctly parses payloads' do
      expect(tx.hash).to be_nil
      expect(tx.parse_data(payloads[0])).to be true
      expect(tx.hash.size).to eq(64)
      expect(tx.payload).to eq(payloads[0])
    end

    it 'parses additional payload data' do
      expect(tx.parse_data(payloads[0] + 'AAAA')).to eq('AAAA')
      expect(tx.hash.size).to eq(64)
      expect(tx.payload).to eq(payloads[0])
    end
  end

  describe '#parse_witness_data' do
    it 'correctly parses witness data' do
      tx = Bitcoin::Protocol::Tx.new(payloads[3])
      expect(tx.hash.size).to eq(64)
      expect(tx.payload).to eq(payloads[3])
    end

    it 'ignores additional payload data' do
      tx = Bitcoin::Protocol::Tx.new(payloads[3] + 'AAAA')
      expect(tx.hash.size).to eq(64)
      expect(tx.payload).to eq(payloads[3])
    end
  end

  describe '#hash' do
    it 'produces the expected hash and binary hash' do
      tx = Bitcoin::Protocol::Tx.new(payloads[0])
      expect(tx.hash.size).to eq(64)
      expect(tx.hash)
        .to eq('6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb28e59f2d02b4')
      expect(tx.binary_hash)
        .to eq("\xB4\x02-\x9F\xE5(\xFB\x90pP\x01\x16K\f\xC3\xA8\xF5\xA1\x9C" \
               "\xB8\xED\x02\xBF\xD4\xFC,\xB6%f\xD1\x9Dn")

      tx = Bitcoin::Protocol::Tx.new(payloads[3])
      expect(tx.hash.size).to eq(64)
      expect(tx.hash)
        .to eq('f22f5168cf0bc55a31003b0fc532152da551e1ec4289c4fd92e7ec512c6e87a0')
    end
  end

  describe '#witness_hash' do
    it 'produces the expected witness hash' do
      tx = Bitcoin::Protocol::Tx.new(payloads[3])
      expect(tx.witness_hash.size).to eq(64)
      expect(tx.witness_hash)
        .to eq('c9609ed4d7e60ebcf4cce2854568b54a855a12b5bda15433ca96e72cd445a5cf')
    end
  end

  describe '#normalized_hash' do
    it 'produces the expected normalized hash' do
      tx = Bitcoin::Protocol::Tx.new(payloads[0])
      expect(tx.normalized_hash.size).to eq(64)
      expect(tx.normalized_hash)
        .to eq('393a12b91d5b5e2449f2d27a22ffc0af937c3796a08c8213cc37690b10302e40')

      new_tx = JSON.parse(tx.to_json)
      script = Bitcoin::Script.from_string(new_tx['in'][0]['scriptSig'])
      script.chunks[0].bitcoin_pushdata = Bitcoin::Script::OP_PUSHDATA2
      script.chunks[0].bitcoin_pushdata_length = script.chunks[0].bytesize
      new_tx['in'][0]['scriptSig'] = script.to_string
      new_tx = Bitcoin::Protocol::Tx.from_hash(new_tx, false)

      expect(new_tx.hash).not_to eq(tx.hash)
      expect(new_tx.normalized_hash.size).to eq(64)
      expect(new_tx.normalized_hash)
        .to eq('393a12b91d5b5e2449f2d27a22ffc0af937c3796a08c8213cc37690b10302e40')
    end
  end

  describe '#to_payload' do
    it 'produces the expected payloads' do
      tx = Bitcoin::Protocol::Tx.new(payloads[0])
      expect(tx.to_payload.size).to eq(payloads[0].size)
      expect(tx.to_payload).to eq(payloads[0])
    end
  end

  describe '#to_witness_payload' do
    it 'produces the expected payloads' do
      tx = Bitcoin::Protocol::Tx.new(payloads[3])
      expect(tx.to_witness_payload.size).to eq(payloads[3].size)
      expect(tx.to_witness_payload).to eq(payloads[3])
    end
  end

  it '#to_hash' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.to_hash.keys)
      .to eq(%w[hash ver vin_sz vout_sz lock_time size in out])

    # witness tx
    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.to_hash.keys)
      .to eq(%w[hash ver vin_sz vout_sz lock_time size in out])
  end

  it '.from_hash' do
    orig_tx = Bitcoin::Protocol::Tx.new(payloads[0])
    tx = Bitcoin::Protocol::Tx.from_hash(orig_tx.to_hash)
    expect(tx.payload).to eq(payloads[0])
    expect(tx.to_payload.size).to eq(payloads[0].size)
    expect(tx.to_payload).to eq(payloads[0])
    expect(tx.to_hash).to eq(orig_tx.to_hash)
    expect(Bitcoin::Protocol::Tx.binary_from_hash(orig_tx.to_hash))
      .to eq(payloads[0])

    h = orig_tx.to_hash.merge('ver' => 123)
    expect do
      Bitcoin::Protocol::Tx.from_hash(h)
    end.to raise_error(Exception,
                       'Tx hash mismatch! Claimed: ' \
                       '6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb2' \
                       '8e59f2d02b4, Actual: 395cd28c334ac84ed125ec5ccd5bc29ea' \
                       'dcc96b79c337d0a87a19df64ea3b548')

    # witness tx(P2WPKH)
    orig_tx = Bitcoin::Protocol::Tx.new(payloads[3])
    tx = Bitcoin::Protocol::Tx.from_hash(orig_tx.to_hash)
    expect(tx.payload).to eq(payloads[3])
    expect(tx.to_witness_payload.size).to eq(payloads[3].size)
    expect(tx.to_witness_payload).to eq(payloads[3])
    expect(tx.to_hash).to eq(orig_tx.to_hash)
  end

  it '.binary_from_hash' do
    orig_tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(Bitcoin::Protocol::Tx.binary_from_hash(orig_tx.to_hash).size).to eq(payloads[0].size)
    expect(Bitcoin::Protocol::Tx.binary_from_hash(orig_tx.to_hash)).to eq(payloads[0])

    orig_tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(Bitcoin::Protocol::Tx.binary_from_hash(orig_tx.to_hash).size).to eq(payloads[3].size)
    expect(Bitcoin::Protocol::Tx.binary_from_hash(orig_tx.to_hash)).to eq(payloads[3])
  end

  it '#to_json' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.to_json).to eq(json[0])

    tx = Bitcoin::Protocol::Tx.new(payloads[1])
    expect(tx.to_json).to eq(json[1])

    tx = Bitcoin::Protocol::Tx.new(payloads[2])
    expect(tx.to_json).to eq(json[2])

    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin')
    )
    expect(tx.to_json)
      .to eq(fixtures_file(
               'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json'
             ))

    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.to_json).to eq(json[3])
  end

  it '.from_json' do
    json_string = fixtures_file(
      'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json'
    )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_json).to eq(json_string)

    json_string = fixtures_file(
      'rawtx-testnet-a220adf1902c46a39db25a24bc4178b6a88440f977a7e2cabfdd8b5c1dd35cfb.json'
    )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_json).to eq(json_string)

    json_string = fixtures_file(
      'rawtx-testnet-e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f.json'
    )
    binary_string = fixtures_file(
      'rawtx-testnet-e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f.bin'
    )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_payload).to eq(binary_string)
    expect(tx.to_json).to eq(json_string)

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json'
      )
    )
    expect(Bitcoin::Protocol::Tx.new(tx.to_payload).to_json)
      .to eq(tx.to_json)
    expect(tx.hash)
      .to eq('ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5')

    # coinbase tx with non-default sequence
    json_string = fixtures_file(
      '0961c660358478829505e16a1f028757e54b5bbf9758341a7546573738f31429.json'
    )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(Bitcoin::Protocol::Tx.new(tx.to_payload).to_json).to eq(json_string)

    # TODO: Deprecate this since Toshi is no longer maintained?
    # toshi format
    expect(
      Bitcoin::Protocol::Tx.from_json(
        fixtures_file('rawtx-02-toshi.json')
      ).to_payload
    ).to eq(
      Bitcoin::Protocol::Tx.from_json(fixtures_file('rawtx-02.json')).to_payload
    )
    expect(
      Bitcoin::Protocol::Tx.from_json(
        fixtures_file('rawtx-03-toshi.json')
      ).to_payload
    ).to eq(
      Bitcoin::Protocol::Tx.from_json(fixtures_file('rawtx-03.json')).to_payload
    )
    expect(
      Bitcoin::Protocol::Tx.from_json(
        fixtures_file('coinbase-toshi.json')
      ).to_payload
    ).to eq(
      Bitcoin::Protocol::Tx.from_json(fixtures_file('coinbase.json')).to_payload
    )

    # witness tx
    json_string = fixtures_file('rawtx-p2wpkh.json')
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_witness_payload).to eq(payloads[3])
    expect(tx.to_json).to eq(json_string)
  end

  it '.binary_from_json' do
    json_string = fixtures_file(
      'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json'
    )
    binary_string = fixtures_file(
      'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin'
    )
    expect(Bitcoin::Protocol::Tx.binary_from_json(json_string))
      .to eq(binary_string)
  end

  describe '.compare_big_endian' do
    it 'compares arrays of bytes' do
      # This function is used in validating an ECDSA signature's S value
      c1 = []
      c2 = []
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)

      c1 = [0]
      c2 = []
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)

      c1 = []
      c2 = [0]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)

      c1 = [5]
      c2 = [5]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)

      c1 = [4]
      c2 = [5]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(-1)

      c1 = [4]
      c2 = [5]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(-1)

      c1 = [5]
      c2 = [4]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(1)

      c1 = [5]
      c2 = [4]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(1)
    end
  end

  describe '.is_der_signature?' do
    it 'validates ECDSA signature format' do
      # TX 3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae
      sig_orig = [
        '304502210088984573e3e4f33db7df6aea313f1ce67a3ef3532ea89991494c7f0182' \
        '58371802206ceefc9291450dbd40d834f249658e0f64662d52a41cf14e20c9781144' \
        'f2fe0701'
      ].pack('H*')
      expect(Bitcoin::Script.is_der_signature?(sig_orig)).to be true
      expect(Bitcoin::Script.is_defined_hashtype_signature?(sig_orig)).to be true

      # Trimmed to be too short
      sig = sig_orig.slice(0, 8)
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Zero-padded to be too long
      sig = String.new(sig_orig)
      sig << 0x00
      sig << 0x00
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Wrong first byte
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[0] = 0x20
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Length byte broken
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[1] = 0x20
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Incorrect R value type
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[2] = 0x03
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # R value length infeasibly long
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[3] = sig_orig.size - 4
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Negative R value
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[4] = 0x80 | sig_bytes[4]
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # R value excessively padded
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[5] = 0x00
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Incorrect S value type
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[37] = 0x03
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Zero S length
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[38] = 0x00
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Negative S value
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[39] = 0x80 | sig_bytes[39]
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false
    end
  end

  it '#verify_input_signature' do
    # transaction-2 of block-170
    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.bin'
      )
    )
    expect(tx.hash)
      .to eq('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16')

    # transaction-1 (coinbase) of block-9
    outpoint_tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9.bin'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9')

    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # Only one test where we provide the TxOut is needed since when providing
    # the full outpoint_tx the verification logic doesn't change.
    expect(tx.verify_input_signature(0, outpoint_tx.out[0])).to be true

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'rawtx-c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73.json'
      )
    )
    expect(tx.hash)
      .to eq('c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73')

    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'rawtx-406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae.json'
      )
    )
    expect(tx.hash)
      .to eq('0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # SIGHASH_ANYONECANPAY transaction
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e.json'
      )
    )
    expect(tx.hash)
      .to eq('51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '761d8c5210fdfd505f6dff38f740ae3728eb93d7d0971fb433f685d40a4c04f6.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('761d8c5210fdfd505f6dff38f740ae3728eb93d7d0971fb433f685d40a4c04f6')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # BIP12/OP_EVAL does't exist.
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99.json'
      )
    )
    expect(tx.hash)
      .to eq('03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE) p2sh transaction
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d.json'
      )
    )
    expect(tx.hash)
      .to eq('7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # SIGHHASH_SINGLE - https://bitcointalk.org/index.php?topic=260595.0
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f.json'
      )
    )
    expect(tx.hash)
      .to eq('315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '69216b8aaa35b76d6613e5f527f4858640d986e1046238583bdad79b35e938dc.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('69216b8aaa35b76d6613e5f527f4858640d986e1046238583bdad79b35e938dc')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true
    expect(tx.verify_input_signature(1, outpoint_tx)).to be true

    # 0:1:01 <signature> 0:1:01 0:1:00 <pubkey> OP_SWAP OP_1ADD OP_CHECKMULTISIG
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2.json'
      )
    )
    expect(tx.hash)
      .to eq('cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # OP_CHECKSIG with OP_0 from mainnet
    # a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954 output 0
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28.json'
      )
    )
    expect(tx.hash)
      .to eq('9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop OP_CODESEPARATOR in subscript for signature_hash_for_input
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa.json'
      )
    )
    expect(tx.hash)
      .to eq('46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop OP_CODESEPARATOR in subscript for signature_hash_for_input
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8.json'
      )
    )
    expect(tx.hash)
      .to eq('aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop multisig OP_CODESEPARATOR in subscript for signature_hash_for_input
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190.json'
      )
    )
    expect(tx.hash)
      .to eq('6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop multisig OP_CODESEPARATOR in subscript for signature_hash_for_input
    # when used in ScriptSig
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb.json'
      )
    )
    expect(tx.hash)
      .to eq('eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d')
    expect(tx.verify_input_signature(1, outpoint_tx)).to be true

    # OP_DUP OP_HASH160
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f.json'
      )
    )
    expect(tx.hash)
      .to eq('5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742')
    expect(tx.verify_input_signature(1, outpoint_tx)).to be true

    # testnet3 e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009.json'
      )
    )
    expect(tx.hash)
      .to eq('e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009')
    prev_txs = {}

    tx.in.map(&:previous_output).uniq.each do |i|
      prev_txs[i] = Bitcoin::Protocol::Tx.from_json(
        fixtures_file("tx-#{i}.json")
      )
    end

    tx.in.each.with_index do |i, idx|
      expect(
        tx.verify_input_signature(idx, prev_txs[i.previous_output])
      ).to be true
    end

    # BIP62 rule #2 - spend transaction has operations in its signature
    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-testnet-3bc52ac063291ad92d95ddda5fd776a342083b95607ad32ed8bc6f8f7d30449e.bin'
      )
    )
    expect(tx.hash)
      .to eq('3bc52ac063291ad92d95ddda5fd776a342083b95607ad32ed8bc6f8f7d30449e')
    outpoint_tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-testnet-04fdc38d6722ab4b12d79113fc4b2896bdcc5169710690ee4e78541b98e467b4.bin'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('04fdc38d6722ab4b12d79113fc4b2896bdcc5169710690ee4e78541b98e467b4')
    expect(
      tx.verify_input_signature(0, outpoint_tx, Time.now.to_i)
    ).to be true
    expect(
      tx.verify_input_signature(
        0, outpoint_tx, Time.now.to_i, verify_sigpushonly: true
      )
    ).to be false

    # BIP62 rule #6 - spend transaction has an unused "0" on the signature stack
    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-testnet-0b294c7d11dd21bcccb8393e6744fed7d4d1981a08c00e3e88838cc421f33c9f.bin'
      )
    )
    expect(tx.hash)
      .to eq('0b294c7d11dd21bcccb8393e6744fed7d4d1981a08c00e3e88838cc421f33c9f')
    outpoint_tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-testnet-f80acbd2f594d04ddb0e1cacba662132104909157dff526935a3c88abe9201a5.bin'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('f80acbd2f594d04ddb0e1cacba662132104909157dff526935a3c88abe9201a5')
    expect(
      tx.verify_input_signature(0, outpoint_tx, Time.now.to_i)
    ).to be true
    expect(
      tx.verify_input_signature(
        0, outpoint_tx, Time.now.to_i, verify_cleanstack: true
      )
    ).to be false

    # Ensure BIP62 is applied to P2SH scripts
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d.json'
      )
    )
    expect(tx.hash)
      .to eq('7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d')

    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true
    expect(
      tx.verify_input_signature(
        0, outpoint_tx, Time.now.to_i, verify_low_s: true
      )
    ).to be false

    # testnet3 P2SH check
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '156e6e1b84c5c3bd3a0927b25e4119fadce6e6d5186f363317511d1d680fae9a.json'
      )
    )
    expect(tx.hash)
      .to eq('156e6e1b84c5c3bd3a0927b25e4119fadce6e6d5186f363317511d1d680fae9a')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '8d0b238a06b5a70be75d543902d02d7a514d68d3252a949a513865ac3538874c.json'
      )
    )
    expect(outpoint_tx.hash)
      .to eq('8d0b238a06b5a70be75d543902d02d7a514d68d3252a949a513865ac3538874c')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true
  end

  it '#verify_witness_input_signature' do
    # P2WPKH
    tx = Bitcoin::Protocol::Tx.new(
      '01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4' \
      'e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3beb' \
      'f337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede9' \
      '44ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b' \
      '309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a914' \
      '8280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143b' \
      'de42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7' \
      'd30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c45183315' \
      '61406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368d' \
      'a1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000'.htb
    )
    expect(
      tx.verify_witness_input_signature(
        1, '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'.htb, 600_000_000
      )
    ).to be true

    # P2WSH
    tx = Bitcoin::Protocol::Tx.new(
      '01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b' \
      '9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6' \
      'c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367' \
      '096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac' \
      '6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a3' \
      '0741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf452778' \
      '9bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd3471' \
      '71cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b' \
      '740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6' \
      'a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749ad' \
      'c2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626a' \
      'ebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000'.htb
    )
    expect(
      tx.verify_witness_input_signature(
        1,
        '00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0'.htb,
        4_900_000_000
      )
    ).to be true

    # P2SH-P2WPKH
    tx = Bitcoin::Protocol::Tx.new(
      '01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3c' \
      'eb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffff' \
      'ff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388' \
      'ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac' \
      '02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d1' \
      '2d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe' \
      '9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2' \
      '687392040000'.htb
    )
    expect(
      tx.verify_witness_input_signature(
        0,
        'a9144733f37cf4db86fbc2efed2500b4f4e49f31202387'.htb,
        1_000_000_000
      )
    ).to be true

    # P2SH-P2WSH
    tx = Bitcoin::Protocol::Tx.new(
      '0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca2' \
      '9787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1b' \
      'b8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc' \
      '0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e' \
      '6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52e' \
      'eb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e' \
      '4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009' \
      'a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62' \
      'e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfe' \
      'c54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a8913' \
      '9c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b' \
      '79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265' \
      'f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553b' \
      'a89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5' \
      'd4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1' \
      '482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a' \
      '34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae' \
      '49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28' \
      'bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703' \
      '413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb8' \
      '33092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94b' \
      'a04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2' \
      'f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000'.htb
    )
    expect(
      tx.verify_witness_input_signature(
        0, 'a9149993a429037b5d912407a71c252019287b8d27a587'.htb, 987_654_321
      )
    ).to be true
  end

  describe '#signature_hash_for_input' do
    it 'sighash_all' do
      prev_tx = Bitcoin::Protocol::Tx.new(
        fixtures_file(
          'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin'
        )
      )
      expect(prev_tx.hash)
        .to eq('2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a')

      pubkey =
        '04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa155' \
        '2e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3'
      key = Bitcoin.open_key(
        '56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc',
        pubkey
      )
      new_tx = Bitcoin::Protocol::Tx.new(nil)
      new_tx.add_in(Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0, 0))
      new_tx.add_out(
        Bitcoin::Protocol::TxOut.value_to_address(
          1_000_000,
          '1BVJWLTCtjA8wRivvrCiwjNdL6KjdMUCTZ'
        )
      )
      signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
      sig = Bitcoin.sign_data(key, signature_hash)
      new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(
        sig, [pubkey].pack('H*')
      )

      new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
      expect(new_tx.hash).not_to be_nil
      expect(new_tx.verify_input_signature(0, prev_tx)).to be true

      prev_tx = Bitcoin::Protocol::Tx.new(
        fixtures_file(
          'rawtx-14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984.bin'
        )
      )
      expect(prev_tx.hash)
        .to eq('14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984')

      pubkey =
        '0409d103127d26ce93ee41f1b9b1ed4c1c243acf48e31eb5c4d88ad0342ccc010a1a' \
        '8d838846cf7337f2b44bc73986c0a3cb0568fa93d068b2c8296ce8d47b1545'
      key = Bitcoin.open_key(
        '115ceda6c1e02d41ce65c35a30e82fb325fe3f815898a09e1a5d28bb1cc92c6e',
        pubkey
      )
      new_tx = Bitcoin::Protocol::Tx.new(nil)
      new_tx.add_in(Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0, 0))
      pk_script = Bitcoin::Script.to_address_script(
        '1FEYAh1x5jeKQMPPuv3bKnKvbgVAqXvqjW'
      )
      new_tx.add_out(
        Bitcoin::Protocol::TxOut.new(1_000_000, pk_script)
      )
      signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
      sig = Bitcoin.sign_data(key, signature_hash)
      new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(
        sig, [pubkey].pack('H*')
      )

      new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
      expect(new_tx.hash).not_to be_nil
      expect(new_tx.verify_input_signature(0, prev_tx)).to be true

      prev_tx = Bitcoin::Protocol::Tx.new(
        fixtures_file(
          'rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin'
        )
      )
      expect(prev_tx.hash)
        .to eq('b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d')

      pubkey = '04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef03' \
               '0eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc' \
               '3a52caf3'
      key = Bitcoin.open_key(
        '56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc',
        pubkey
      )
      new_tx = Bitcoin::Protocol::Tx.new(nil)
      new_tx.add_in(
        Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0, 0)
      )
      new_tx.add_out(
        Bitcoin::Protocol::TxOut.value_to_address(
          1_000_000, '14yz7fob6Q16hZu4nXfmv1kRJpSYaFtet5'
        )
      )
      signature_hash = new_tx.signature_hash_for_input(0, prev_tx)
      sig = Bitcoin.sign_data(key, signature_hash)
      new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(
        sig, [pubkey].pack('H*')
      )

      new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
      expect(new_tx.hash).not_to be_nil
      expect(new_tx.verify_input_signature(0, prev_tx)).to be true
    end

    it 'sighash JSON tests' do
      test_cases = JSON.parse(fixtures_file('sighash.json'))

      test_cases.each do |test_case|
        # Single element arrays in tests are comments.
        next if test_case.length == 1

        transaction = Bitcoin::Protocol::Tx.new(test_case[0].htb)
        subscript = test_case[1].htb
        input_index = test_case[2].to_i
        hash_type = test_case[3]
        amount = 0
        expected_sighash = test_case[4].htb_reverse

        actual_sighash = transaction.signature_hash_for_input(
          input_index, subscript, hash_type, amount, 0
        )
        expect(actual_sighash).to eq(expected_sighash)
      end
    end
  end

  it '#signature_hash_for_witness_input' do
    # P2WPKH
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Native_P2WPKH
    tx = Bitcoin::Protocol::Tx.new(
      '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad' \
      '969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9' \
      'b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df3' \
      '78db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e' \
      '4dbe6a21b2d50ce2f0167faa815988ac11000000'.htb
    )
    signature_hash = tx.signature_hash_for_witness_input(
      1, '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'.htb, 600_000_000
    )
    expect(signature_hash.bth)
      .to eq('c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')

    # P2WSH
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Native_P2WSH
    tx = Bitcoin::Protocol::Tx.new(
      '0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216' \
      'b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47' \
      'c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f814' \
      '5e5acadf23f751864167f32e0963f788ac00000000'.htb
    )
    script_pubkey =
      '00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0'
    witness_script =
      '21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aead' \
      'ab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac'
    signature_hash = tx.signature_hash_for_witness_input(
      1, script_pubkey.htb, 4_900_000_000,
      witness_script.htb, Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single]
    )
    expect(signature_hash.bth)
      .to eq('82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391')

    # P2WSH with invalid witness script
    tx = Bitcoin::Protocol::Tx.new(
      '0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b921' \
      '6b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da' \
      '47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f' \
      '8145e5acadf23f751864167f32e0963f788ac00000000'.htb
    )
    script_pubkey =
      '00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0'
    witness_script = 'AAA'
    expect do
      tx.signature_hash_for_witness_input(
        1, script_pubkey.htb, 4_900_000_000, witness_script.htb
      )
    end.to raise_error(
      RuntimeError, 'witness script does not match script pubkey'
    )
  end

  it '#legacy_sigops_count' do
    expect(Bitcoin::Protocol::Tx.new(payloads[0]).legacy_sigops_count).to eq(2)
    expect(Bitcoin::Protocol::Tx.new(payloads[1]).legacy_sigops_count).to eq(2)
    expect(Bitcoin::Protocol::Tx.new(payloads[2]).legacy_sigops_count).to eq(2)

    # Test sig ops count in inputs too.
    tx = Bitcoin::Protocol::Tx.new
    txin = Bitcoin::Protocol::TxIn.new
    txin.script_sig = Bitcoin::Script.from_string(
      '10 OP_CHECKMULTISIGVERIFY OP_CHECKSIGVERIFY'
    ).to_binary
    tx.add_in(txin)
    txout = Bitcoin::Protocol::TxOut.new
    txout.pk_script = Bitcoin::Script.from_string(
      '5 OP_CHECKMULTISIG OP_CHECKSIG'
    ).to_binary
    tx.add_out(txout)

    expect(tx.legacy_sigops_count).to eq(20 + 1 + 20 + 1)
  end

  describe 'Tx - final?' do
    it 'should be final if lock_time == 0' do
      tx = Bitcoin::Protocol::Tx.new
      tx.lock_time = 0
      expect(tx.final?(0, 0)).to be true

      # even if has non-final input:
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      expect(tx.final?(0, 0)).to be true
    end

    it 'should be final if lock_time is below block_height' do
      tx = Bitcoin::Protocol::Tx.new
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.lock_time = 6543

      expect(tx.final?(6000, 0)).to be false
      # when equal to block height, still not final
      expect(tx.final?(6543, 0)).to be false
      expect(tx.final?(6544, 0)).to be true
      expect(tx.final?(9999, 0)).to be true
    end

    it 'should be final if lock_time is below timestamp' do
      tx = Bitcoin::Protocol::Tx.new
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD # when equal, interpreted as threshold
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD - 1)).to be false
      # when equal to timestamp, still not final
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD)).to be false
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be true

      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD + 666
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be false
      # when equal to timestamp, still not final
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 666)).to be false
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 667)).to be true
    end

    it 'should be final if all inputs are finalized regardless of lock_time' do
      tx = Bitcoin::Protocol::Tx.new
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)

      tx.lock_time = 6543
      expect(tx.final?(6000, 0)).to be true
      expect(tx.final?(6543, 0)).to be true
      expect(tx.final?(6544, 0)).to be true
      expect(tx.final?(9999, 0)).to be true

      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD - 1)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be true

      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD + 666
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 666)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 667)).to be true
    end
  end

  it '#calculate_minimum_fee' do
    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin'
      )
    )
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(0)
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'bc179baab547b7d7c1d5d8d6f8b0cc6318eaa4b0dd0a093ad6ac7f5a1cb6b3ba.json'
      )
    )
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(10_000)
  end

  it '#calculate_minimum_fee for litecoin' do
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'litecoin-tx-f5aa30f574e3b6f1a3d99c07a6356ba812aabb9661e1d5f71edff828cbd5c996.json'
      )
    )
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(30_000)

    Bitcoin.network = :litecoin # change to litecoin
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(100_000)
  end

  it 'should compare transactions' do
    tx1 = Bitcoin::Protocol::Tx.new(payloads[0])
    tx2 = Bitcoin::Protocol::Tx.new(payloads[1])

    expect(Bitcoin::Protocol::Tx.from_json(tx1.to_json)).to eq(tx1)
    expect(tx1).not_to eq(tx2)
    expect(tx1).not_to be_nil
  end

  describe 'Tx - BIP Scripts' do
    it 'should do OP_CHECKMULTISIG' do
      # checkmultisig without checkhashverify
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          '23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63.json'
        )
      )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          '60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1.json'
        )
      )
      expect(tx.verify_input_signature(0, prev_tx)).to be true

      # p2sh + multisig transaction from mainnet
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json'
        )
      )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'rawtx-de35d060663750b3975b7997bde7fb76307cec5b270d12fcd9c4ad98b279c28c.json'
        )
      )
      expect(tx.verify_input_signature(0, prev_tx)).to be true

      # checkmultisig for testnet3 tx:
      # 2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1 input
      # index 1
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1.json'
        )
      )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-19aa42fee0fa57c45d3b16488198b27caaacc4ff5794510d0c17f173f05587ff.json'
        )
      )
      expect(tx.verify_input_signature(1, prev_tx)).to be true
    end

    it 'should do P2SH with inner OP_CHECKMULTISIG (BIP 0016)' do
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          '3a17dace09ffb919ed627a93f1873220f4c975c1248558b18d16bce25d38c4b7.json'
        )
      )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          '35e2001b428891fefa0bfb73167c7360669d3cbd7b3aa78e7cad125ddfc51131.json'
        )
      )
      expect(tx.verify_input_signature(0, prev_tx)).to be true

      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'bd1715f1abfdc62bea3f605bdb461b3ba1f2cca6ec0d73a18a548b7717ca8531.json'
        )
      )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'ce5fad9b4ef094d8f4937b0707edaf0a6e6ceeaf67d5edbfd51f660eac8f398b.json'
        )
      )
      expect(tx.verify_input_signature(1, prev_tx)).to be true

      # p2sh transaction with non-standard OP_CHECKMULTISIG inside found in
      # testnet3 tx:
      # d3d77d63709e47d9ef58f0b557800115a6b676c6a423012fbb96f45d8fcef830
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-d3d77d63709e47d9ef58f0b557800115a6b676c6a423012fbb96f45d8fcef830.json'
        )
      )
      expect(tx.hash)
        .to eq('d3d77d63709e47d9ef58f0b557800115a6b676c6a423012fbb96f45d8fcef830')
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-313897799b1e37e9ecae15010e56156dddde4e683c96b0e713af95272c38aee0.json'
        )
      )
      expect(prev_tx.hash)
        .to eq('313897799b1e37e9ecae15010e56156dddde4e683c96b0e713af95272c38aee0')
      expect(tx.verify_input_signature(0, prev_tx)).to be true
    end

    it 'should do P2SH with inner OP_CHECKSIG' do
      # p2sh transaction with non-standard OP_CHECKSIG inside found in testnet3
      # tx: 3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae.json'
        )
      )
      expect(tx.hash)
        .to eq('3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae')
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-44b833074e671120ba33106877b49e86ece510824b9af477a3853972bcd8d06a.json'
        )
      )
      expect(prev_tx.hash)
        .to eq('44b833074e671120ba33106877b49e86ece510824b9af477a3853972bcd8d06a')
      expect(tx.verify_input_signature(0, prev_tx)).to be true
    end

    it 'should do OP_CHECKMULTISIG with OP_0 used as a pubkey' do
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-6606c366a487bff9e412d0b6c09c14916319932db5954bf5d8719f43f828a3ba.json'
        )
      )
      expect(tx.hash)
        .to eq('6606c366a487bff9e412d0b6c09c14916319932db5954bf5d8719f43f828a3ba')
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-4142ee4877eb116abf955a7ec6ef2dc38133b793df762b76d75e3d7d4d8badc9.json'
        )
      )
      expect(prev_tx.hash)
        .to eq('4142ee4877eb116abf955a7ec6ef2dc38133b793df762b76d75e3d7d4d8badc9')
      expect(tx.verify_input_signature(0, prev_tx)).to be true
    end
  end

  it 'lexicographical_sort' do
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-0a6a357e2f7796444e02638749d9611c008b253fb55f5dc88b739b230ed0c4c3.json'
      )
    )
    expect(tx.hash)
      .to eq('0a6a357e2f7796444e02638749d9611c008b253fb55f5dc88b739b230ed0c4c3')

    tx.lexicographical_sort!
    expect(tx.in[0].previous_output)
      .to eq('0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57')
    expect(tx.in[1].previous_output)
      .to eq('26aa6e6d8b9e49bb0630aac301db6757c02e3619feb4ee0eea81eb1672947024')
    expect(tx.in[2].previous_output)
      .to eq('28e0fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2')
    expect(tx.in[3].previous_output)
      .to eq('381de9b9ae1a94d9c17f6a08ef9d341a5ce29e2e60c36a52d333ff6203e58d5d')
    expect(tx.in[4].previous_output)
      .to eq('3b8b2f8efceb60ba78ca8bba206a137f14cb5ea4035e761ee204302d46b98de2')
    expect(tx.in[5].previous_output)
      .to eq('402b2c02411720bf409eff60d05adad684f135838962823f3614cc657dd7bc0a')
    expect(tx.in[6].previous_output)
      .to eq('54ffff182965ed0957dba1239c27164ace5a73c9b62a660c74b7b7f15ff61e7a')
    expect(tx.in[7].previous_output)
      .to eq('643e5f4e66373a57251fb173151e838ccd27d279aca882997e005016bb53d5aa')
    expect(tx.in[8].previous_output)
      .to eq('6c1d56f31b2de4bfc6aaea28396b333102b1f600da9c6d6149e96ca43f1102b1')
    expect(tx.in[9].previous_output)
      .to eq('7a1de137cbafb5c70405455c49c5104ca3057a1f1243e6563bb9245c9c88c191')
    expect(tx.in[10].previous_output)
      .to eq('7d037ceb2ee0dc03e82f17be7935d238b35d1deabf953a892a4507bfbeeb3ba4')
    expect(tx.in[11].previous_output)
      .to eq('a5e899dddb28776ea9ddac0a502316d53a4a3fca607c72f66c470e0412e34086')
    expect(tx.in[12].previous_output)
      .to eq('b4112b8f900a7ca0c8b0e7c4dfad35c6be5f6be46b3458974988e1cdb2fa61b8')
    expect(tx.in[13].previous_output)
      .to eq('bafd65e3c7f3f9fdfdc1ddb026131b278c3be1af90a4a6ffa78c4658f9ec0c85')
    expect(tx.in[14].previous_output)
      .to eq('de0411a1e97484a2804ff1dbde260ac19de841bebad1880c782941aca883b4e9')
    expect(tx.in[15].previous_output)
      .to eq('f0a130a84912d03c1d284974f563c5949ac13f8342b8112edff52971599e6a45')
    expect(tx.in[16].previous_output)
      .to eq('f320832a9d2e2452af63154bc687493484a0e7745ebd3aaf9ca19eb80834ad60')
    expect(tx.out[0].value).to eq(400_057_456)
    expect(tx.out[1].value).to eq(40_000_000_000)

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f.json'
      )
    )
    expect(tx.hash)
      .to eq('28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f')

    tx.lexicographical_sort!
    expect(tx.in[0].previous_output)
      .to eq('35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055')
    expect(tx.in[0].prev_out_index).to eq(0)
    expect(tx.in[1].previous_output)
      .to eq('35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055')
    expect(tx.in[1].prev_out_index).to eq(1)
    expect(tx.out[0].value).to eq(100_000_000)
    expect(tx.out[1].value).to eq(2_400_000_000)

    tx = Bitcoin::Protocol::Tx.new
    tx.add_out(Bitcoin::Protocol::TxOut.new(500, 'bbbbbbbb'.htb))
    tx.add_out(Bitcoin::Protocol::TxOut.new(500, 'aaaaaaaa'.htb))
    tx.add_out(Bitcoin::Protocol::TxOut.new(500, 'cccccccc'.htb))

    tx.lexicographical_sort!
    expect(tx.out[0].pk_script.bth).to eq('aaaaaaaa')
    expect(tx.out[1].pk_script.bth).to eq('bbbbbbbb')
    expect(tx.out[2].pk_script.bth).to eq('cccccccc')
  end

  describe 'verify_input_signature' do
    # rubocop:disable Metrics/CyclomaticComplexity
    def parse_script(script_str)
      script = Bitcoin::Script.new('')

      # Disabling the below rubocop check since the proposed fix does not work
      # on Ruby versions < 2.3. If we ever drop support for these then it can be
      # fixed

      buf = ''.dup

      script_str.split.each do |token|
        opcode = Bitcoin::Script::OPCODES_PARSE_STRING[token] ||
                 Bitcoin::Script::OPCODES_PARSE_STRING['OP_' + token]
        if opcode
          buf << [opcode].pack('C')
          next
        end

        data =
          case token
          when /\A-?\d+\z/
            i = token.to_i
            opcode =
              case i
              when -1 then Bitcoin::Script::OP_1NEGATE
              when 0 then Bitcoin::Script::OP_0
              when 1 then Bitcoin::Script::OP_1
              when 2..16 then Bitcoin::Script::OP_2 + i - 2
              end

            if opcode
              [opcode].pack('C')
            else
              Bitcoin::Script.pack_pushdata(script.cast_to_string(i))
            end
          when /\A'(.*)'\z/ then
            Bitcoin::Script.pack_pushdata(Regexp.last_match(1))
          when /\A0x([0-9a-fA-F]+)\z/ then Regexp.last_match(1).htb
          else raise "Unexpected token #{token}"
          end
        buf << data
      end
      buf
    end

    def parse_flags(flags_str)
      flags_str.split(',').each_with_object({}) do |flag_str, opts|
        case flag_str.to_sym
        when :STRICTENC then opts[:verify_strictenc] = true
        when :DERSIG then opts[:verify_dersig] = true
        when :LOW_S then opts[:verify_low_s] = true
        when :SIGPUSHONLY then opts[:verify_sigpushonly] = true
        when :MINIMALDATA then opts[:verify_minimaldata] = true
        when :CLEANSTACK then opts[:verify_cleanstack] = true
        when :SIGHASH_FORKID then opts[:fork_id] = 0
        end
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity

    it 'script JSON tests' do
      test_cases = JSON.parse(fixtures_file('script_tests.json'))

      test_cases.each do |test_case|
        # Single element arrays in tests are comments.
        next if test_case.length == 1

        value =
          if test_case[0].is_a?(Array)
            (test_case.shift[0] * 10**8).to_i
          else
            0
          end

        # TODO: Implement these opcodes correctly
        # NOTE: Need to use `match` instead of `match?` because Ruby < 2.4 does
        # not support the latter function.

        # rubocop:disable Performance/RedundantMatch
        if test_case[0].match(
          /CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY|RESERVED|0x50|VERIF|VERNOTIF/
        )
          next
        end

        if test_case[1].match(
          /CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY|RESERVED|0x50|VERIF|VERNOTIF/
        )
          next
        end
        # rubocop:enable Performance/RedundantMatch

        script_sig = parse_script(test_case[0])
        script_pubkey = parse_script(test_case[1])
        opts = parse_flags(test_case[2])
        expect_success = test_case[3] == 'OK'

        # A lot of the test cases are failing, so for now we only test the
        # SIGHASH_FORKID ones.
        # TODO: Get this spec passing without this line.
        next unless opts[:fork_id]

        crediting_tx = Bitcoin::Protocol::Tx.new
        crediting_tx.add_in(Bitcoin::Protocol::TxIn.new)
        crediting_tx.in[0].prev_out_hash = Bitcoin::Protocol::TxIn::NULL_HASH
        crediting_tx.in[0].prev_out_index = Bitcoin::Protocol::TxIn::COINBASE_INDEX
        crediting_tx.in[0].script_sig = parse_script('0 0')
        crediting_tx.add_out(Bitcoin::Protocol::TxOut.new)
        crediting_tx.out[0].value = value
        crediting_tx.out[0].pk_script = script_pubkey
        crediting_tx.refresh_hash

        spending_tx = Bitcoin::Protocol::Tx.new
        spending_tx.add_in(Bitcoin::Protocol::TxIn.new)
        spending_tx.in[0].prev_out_hash = crediting_tx.binary_hash
        spending_tx.in[0].prev_out_index = 0
        spending_tx.in[0].script_sig = script_sig
        spending_tx.add_out(Bitcoin::Protocol::TxOut.new)
        spending_tx.out[0].value = value
        spending_tx.out[0].pk_script = ''
        spending_tx.refresh_hash

        success = spending_tx.verify_input_signature(
          0, crediting_tx, Time.now.to_i, opts
        )
        expect(success).to eq(expect_success)
      end
    end
  end
end
