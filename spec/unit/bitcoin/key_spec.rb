# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Key do
  let(:key_data) do
    {
      priv: '2ebd3738f59ae4fd408d717bf325b4cb979a409b0153f6d3b4b91cdfe046fb1e',
      pub: '035fcb2fb2802b024f371cc22bc392268cc579e47e7936e0d1f05064e6e1103b8a'
    }
  end
  let(:key) do
    Bitcoin::Key.new(key_data[:priv], key_data[:pub], false)
  end

  it 'should generate a key' do
    k = Bitcoin::Key.generate
    expect(k.priv.size).to eq(64)
    expect(k.pub.size).to eq(66)
    expect(k.compressed).to be true

    k = Bitcoin::Key.generate(compressed: true)
    expect(k.priv.size).to eq(64)
    expect(k.pub.size).to eq(66)
    expect(k.compressed).to be true

    k = Bitcoin::Key.generate(true)
    expect(k.priv.size).to eq(64)
    expect(k.pub.size).to eq(66)
    expect(k.compressed).to be true

    k = Bitcoin::Key.generate(compressed: false)
    expect(k.priv.size).to eq(64)
    expect(k.pub.size).to eq(130)
    expect(k.compressed).to be false

    k = Bitcoin::Key.generate(false)
    expect(k.priv.size).to eq(64)
    expect(k.pub.size).to eq(130)
    expect(k.compressed).to be false
  end

  it 'should create empty key' do
    k = Bitcoin::Key.new
    expect(k.priv).to be_nil
    expect(k.pub).to be_nil
    expect(k.compressed).to be true
  end

  it 'should create key from priv + pub' do
    k = Bitcoin::Key.new(key_data[:priv], key_data[:pub])
    expect(k.priv).to eq(key_data[:priv])
    expect(k.pub).to eq(key_data[:pub])
  end

  it 'should create key from only priv' do
    k = Bitcoin::Key.new(key_data[:priv])
    expect(k.priv).to eq(key_data[:priv])
    expect(k.pub).to eq(key_data[:pub])
  end

  it 'should create key from only pub' do
    k = Bitcoin::Key.new(nil, key_data[:pub])
    expect(k.pub).to eq(key_data[:pub])
  end

  it 'should set public key' do
    k = Bitcoin::Key.new
    k.pub = key_data[:pub]
    expect(k.pub).to eq(key_data[:pub])
  end

  it 'should set private key' do
    k = Bitcoin::Key.new
    k.priv = key_data[:priv]
    expect(k.priv).to eq(key_data[:priv])
    expect(k.pub).to eq(key_data[:pub])
  end

  it 'should get addr' do
    expect(key.addr).to eq('19CyxBz6CUBogxTdSXUrbRHo7T7eLCMgbr')
    key.instance_eval { @pubkey_compressed = false }
    expect(key.addr).to eq('1JbYZRKyysprVjSSBobs8LX6QVjzsscQNU')
  end

  it 'should sign data' do
    expect(key.sign('foobar').size).to be >= 69
  end

  it 'should verify signature using public key' do
    sig = key.sign('foobar')
    new_key = Bitcoin::Key.new(nil, key.pub)
    expect(new_key.verify('foobar', sig)).to be true
  end

  it 'should verify signature using private key' do
    sig = key.sign('foobar')
    new_key = Bitcoin::Key.new(key.priv)
    expect(new_key.verify('foobar', sig)).to be true
  end

  it 'recovers public keys from compact signatures' do
    tests = [
      # normal
      {
        address: '16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce',
        signature: 'HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDF' \
                   'ORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=',
        message: 'test message',
        expected: true
      },
      # different message
      {
        address: '16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce',
        signature: 'HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDF' \
                   'ORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=',
        message: 'not what I signed',
        expected: false
      },
      # different address
      {
        address: '1JbYZRKyysprVjSSBobs8LX6QVjzsscQNU',
        signature: 'HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDF' \
                   'ORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=',
        message: 'test message',
        expected: false
      },
      # compressed
      {
        address: '18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX',
        signature: 'IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18' \
                   'L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc=',
        message: 'testtest',
        expected: true
      }
    ]

    tests.each do |test|
      key = Bitcoin::Key.recover_compact_signature_to_key(
        test[:message], test[:signature]
      )
      expect(key.addr == test[:address]).to eq(test[:expected])
    end
  end

  it 'should export private key in base58 format' do
    Bitcoin.network = :bitcoin
    str = Bitcoin::Key.new(
      'e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262',
      nil,
      false
    ).to_base58
    expect(str).to eq('5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF')

    Bitcoin.network = :testnet
    str = Bitcoin::Key.new(
      'd21fa2c7ad710ffcd9bcc22a9f96357bda1a2521ca7181dd610140ecea2cecd8',
      nil,
      false
    ).to_base58
    expect(str).to eq('93BTVFoqffueSaC5fqjLjLyn29S41JzvAZm2hC35SYMoYDXT1bY')
  end

  it 'should import private key in base58 format' do
    Bitcoin.network = :bitcoin
    key = Bitcoin::Key.from_base58(
      '5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF'
    )
    expect(key.priv)
      .to eq('e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262')
    expect(key.addr)
      .to eq('1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj')

    Bitcoin.network = :testnet
    key = Bitcoin::Key.from_base58(
      '93BTVFoqffueSaC5fqjLjLyn29S41JzvAZm2hC35SYMoYDXT1bY'
    )
    expect(key.priv)
      .to eq('d21fa2c7ad710ffcd9bcc22a9f96357bda1a2521ca7181dd610140ecea2cecd8')
    expect(key.addr)
      .to eq('n3eH91H14mSnGx4Va2ngtLFCeLPRyYymRg')
  end

  it 'should export private key in compressed base58 format' do
    Bitcoin.network = :bitcoin
    key = Bitcoin::Key.new(
      '98e4483a197fb686fe9afb51389f329aabc67964b1d0e0a5340c962a0d63c44a',
      nil,
      true
    ).to_base58
    expect(key).to eq('L2LusdhGSagfUVvNWrUuPDygn5mdAhxUDEANfABvBj36Twn1mKgQ')

    Bitcoin.network = :testnet3
    key = Bitcoin::Key.new(
      'e3ff5d7e592669d0c1714f1496b260815edd0c3a00186e896dc7f36ede914dd2',
      nil,
      true
    ).to_base58
    expect(key).to eq('cVDu6aXUWHTM2vpztZW14BMnKkCcd5th6177VnCsa8XozoMyp73C')
  end

  it 'should import private key in compressed base58 format' do
    Bitcoin.network = :bitcoin
    key = Bitcoin::Key.from_base58(
      'L2LusdhGSagfUVvNWrUuPDygn5mdAhxUDEANfABvBj36Twn1mKgQ'
    )
    expect(key.priv)
      .to eq('98e4483a197fb686fe9afb51389f329aabc67964b1d0e0a5340c962a0d63c44a')
    expect(key.pub)
      .to eq('02e054ee811165ac294c992ff410067db6491228725fe09db2a415493c897973a8')
    expect(key.compressed).to be true
    expect(key.addr).to eq('1C7Ni4zuV3zfLs8T1S7s29wNAtRoDHHnpw')

    Bitcoin.network = :testnet3
    key = Bitcoin::Key.from_base58(
      'cVDu6aXUWHTM2vpztZW14BMnKkCcd5th6177VnCsa8XozoMyp73C'
    )
    expect(key.priv)
      .to eq('e3ff5d7e592669d0c1714f1496b260815edd0c3a00186e896dc7f36ede914dd2')
    expect(key.pub)
      .to eq('0390bb61c062266a1e8460ec902379749ae30f569013d82bd448a61591f20b8ee2')
    expect(key.addr)
      .to eq('mjh9RgZh14FfJQ2pFpRSqEQ5BH1nHo5To7')
  end

  it 'should handle compressed and uncompressed pubkeys' do
    compressed =
      '0351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da78'
    uncompressed =
      '0451efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da78' \
      '7f71a2e8ac5aacedab47904d4bd42f636429e9ce069ebcb99f675aad31306a53'

    expect(Bitcoin::Key.new(nil, compressed).compressed).to be true
    expect(Bitcoin::Key.new(nil, compressed).pub).to eq(compressed)
    expect(Bitcoin::Key.new(nil, compressed).addr)
      .to eq('1NdB761LmTmrJixxp93nz7pEiCx5cKPW44')
    expect(Bitcoin::Key.new(nil, uncompressed).compressed).to be false
    expect(Bitcoin::Key.new(nil, uncompressed).pub).to eq(uncompressed)
    expect(Bitcoin::Key.new(nil, uncompressed).addr)
      .to eq('19FBCg9295EBQ4P6bSLTGyz2BdbbPcqQD')

    new_key = Bitcoin::Key.new(nil, compressed)
    expect(new_key.pub_compressed).to eq(compressed)
    expect(new_key.pub_uncompressed).to eq(uncompressed)

    msg = 'foobar'
    sig = key.sign(msg)
    expect(Bitcoin::Key.new(nil, key.pub_compressed).verify(msg, sig))
      .to be true
    expect(Bitcoin::Key.new(nil, key.pub_uncompressed).verify(msg, sig))
      .to be true

    compressed =
      '02f01984446a994a9e422c9ba9c6f33f1f40c01d9d872064a49679d702fae33064'
    expect(Bitcoin::Key.new(nil, compressed).pub).to eq(compressed)
    expect(Bitcoin::Key.new(nil, compressed).addr)
      .to eq('18TWywxjESkg4pzJqBYNDo39S2QMPaWWJ5')

    k = Bitcoin::Key.new(nil, nil)
    k.instance_eval do
      set_pub(
        '02f01984446a994a9e422c9ba9c6f33f1f40c01d9d872064a49679d702fae33064'
      )
    end
    expect(k.compressed).to be true

    k = Bitcoin::Key.new(nil, nil)
    k.instance_eval do
      set_pub(
        '0351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da78'
      )
    end
    expect(k.compressed).to be true

    k = Bitcoin::Key.new(nil, nil)
    k.instance_eval do
      set_pub(
        '0451efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da787' \
        'f71a2e8ac5aacedab47904d4bd42f636429e9ce069ebcb99f675aad31306a53'
      )
    end
    expect(k.compressed).to be false
  end

  it 'should handle private key in bip38 (non-ec-multiply) format' do
    k = Bitcoin::Key.from_base58(
      '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
    )
    expect(k.to_bip38('TestingOneTwoThree'))
      .to eq('6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg')

    k = Bitcoin::Key.from_bip38(
      '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg',
      'TestingOneTwoThree'
    )
    expect(k.to_base58)
      .to eq('5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR')

    k = Bitcoin::Key.from_base58(
      '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5'
    )
    expect(k.to_bip38('Satoshi'))
      .to eq('6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq')

    k = Bitcoin::Key.from_bip38(
      '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq',
      'Satoshi'
    )
    expect(k.to_base58)
      .to eq('5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5')

    k = Bitcoin::Key.from_base58(
      'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP'
    )
    expect(k.to_bip38('TestingOneTwoThree'))
      .to eq('6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo')

    k = Bitcoin::Key.from_bip38(
      '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo',
      'TestingOneTwoThree'
    )
    expect(k.to_base58)
      .to eq('L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP')

    k = Bitcoin::Key.from_base58(
      'KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7'
    )
    expect(k.to_bip38('Satoshi'))
      .to eq('6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7')

    k = Bitcoin::Key.from_bip38(
      '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7',
      'Satoshi'
    )
    expect(k.to_base58)
      .to eq('KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7')
  end

  it 'should generate private key from warp format' do
    k = Bitcoin::Key.from_warp('ER8FT+HFjk0', '7DpniYifN6c')
    expect(k.addr).to eq('1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ')
    expect(k.to_base58)
      .to eq('5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD')

    k = Bitcoin::Key.from_warp('YqIDBApDYME', 'G34HqIgjrIc')
    expect(k.addr).to eq('19aKBeXe2mi4NbQRpYUrCLZtRDHDUs9J7J')
    expect(k.to_base58)
      .to eq('5KUJA5iZ2zS7AXkU2S8BiBVY3xj6F8GspLfWWqL9V7CajXumBQV')

    k = Bitcoin::Key.from_warp('FPdAxCygMJg', 'X+qaSwhUYXw')
    expect(k.addr).to eq('14Pqeo9XNRxjtKFFYd6TvRrJuZxVpciS81')
    expect(k.to_base58)
      .to eq('5JBAonQ4iGKFJxENExZghDtAS6YB8BsCw5mwpHSvZvP3Q2UxmT1')
  end

  it 'should raise error for private key out of range.' do
    expect do
      Bitcoin::Key.new(
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
      )
    end.to raise_error(RuntimeError, 'private key is not on curve')

    expect do
      Bitcoin::Key.new('00')
    end.to raise_error(RuntimeError, 'private key is not on curve')

    Bitcoin::Key.new(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140'
    )
    Bitcoin::Key.new('01')
  end

  describe 'Bitcoin::OpenSSL_EC' do
    it 'resolves public from private key' do
      privkey = [
        '56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc'
      ].pack('H*')
      pubkey = [
        '04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030ea' \
        'a1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3'
      ].pack('H*')

      expect(Bitcoin::OpenSSL_EC.regenerate_key(privkey))
        .to eq([privkey, pubkey].map { |i| i.unpack('H*')[0] })

      [
        [
          'b51386f8275d49d8d30287d7b1afa805790bdd1fe8b13d22d25928c67ea55d02',
          '0470305ae5278a22499980286d9c513861d89e7b7317c8b891c554d5c8fdd256' \
          'b03daa0340be4104f8c84cfa98f0da8f16567fcdd3a00fd993adbbe91695671a56'
        ],
        [
          'd8ebece51adc5fb99dd6994bcb8fa1221d01576fd76af9134ab36f8d4698b55c',
          '047503421850d3a6eecb7c9de33b367c4d3f96a34ff257ad0c34e234e29f3672' \
          '525c6b4353ce6fdc9de3f885fdea798982e2252e610065dbdb62cd8cab1fe45822'
        ],
        [
          'c95c79fb0cc1fe47b384751df0627be40bbe481ec94eeafeb6dc40e94c40de43',
          '04b746ca07e718c7ca26d4eeec037492777f48bb5c750e972621698f699f5305' \
          '35c0ffa96dad581102d0471add88e691af85955d1fd42f68506f8092fddfe0c47a'
        ],
        [
          '5b61f807cc938b0fd3ec8f6006737d0002ceca09f296204138c4459de8a856f6',
          '0487357bf30c13d47d955666f42f87690cfd18be96cc74cda711da74bf76b08e' \
          'bc6055aba30680e6288df14bda68c781cbf71eaad096c3639e9724c5e26f3acf54'
        ]
      ].each do |key|
        privkey, pubkey = [key.first].pack('H*')
        expect(Bitcoin::OpenSSL_EC.regenerate_key(privkey)).to eq(key)
      end

      250.times.each do
        keypair = Bitcoin.generate_key
        expect(Bitcoin::OpenSSL_EC.regenerate_key(keypair.first)).to eq(keypair)
      end
    end

    it 'recover public key from compact signature' do
      args = [
        "\x12&\x17\x9D\xDFc\x83\xFB\xCFQ\x02\xC9I%8\xB7 ls\x9A\xE7\x9E\xB0d@" \
        "\x8C*\xBDg\xD3\x9B\xED",
        "\x1C\xF0\xEC\xD57\xAC\x03\x8F\x1A\xF6\xEAx@\xE4H\xBA\xE6\xFA\xEDQ" \
        "\xC13~\xD7\xEB\xAB$\x01\x8C\xF4\x12\xC86\xDE\a_2\xE0\x93`1NE\xCE" \
        "\x97\x1A\x92\x99\xDB\xF7\xE5'h\x7F\rAy\xEB\xD1I\xC4j\x15g\x9D",
        1,
        false
      ]
      expected = '047840b97f46d4c32c62119f9e069172272592ec7741a3aec81e339b873' \
                 '87350740dce89837c8332910f349818060b66070b94e8bb11442d49d3f6' \
                 'c0d7f31ba6a6'

      expect(Bitcoin::OpenSSL_EC.recover_public_key_from_signature(*args))
        .to eq(expected)
    end

    it 'sign and verify text messages' do
      [
        ['5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj', false],
        ['5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3', false],
        ['Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw', true],
        ['L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g', true]
      ].each do |privkey_base58, expected_compression|
        k = Bitcoin::Key.from_base58(privkey_base58)
        expect(k.compressed).to eq(expected_compression)
        k2 = Bitcoin::Key.new(nil, k.pub)
        expect(k2.compressed).to eq(expected_compression)
        16.times do |n|
          msg = "Very secret message #{n}: 11"
          signature = k.sign_message(msg)
          expect(k2.verify_message(signature, msg)).to be true
          expect(Bitcoin::Key.verify_message(k.addr, signature, msg)).to be true
        end
      end
    end
  end
end
