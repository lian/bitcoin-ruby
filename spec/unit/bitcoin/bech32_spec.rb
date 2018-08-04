# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

# rubocop:disable Metrics/LineLength
describe 'Bitcoin::Bech32' do
  # All test vectors in this file come from BIP-173:
  # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

  let(:invalid_address_encs) do
    [
      ['BC', 0, 20],
      ['bc', 0, 21],
      ['bc', 17, 32],
      ['bc', 1, 1],
      ['bc', 16, 41]
    ]
  end
  let(:invalid_addresses) do
    %w[
      tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty
      bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5
      BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2
      bc1rw5uspcuh
      bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90
      BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P
      tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7
      bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du
      tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv
      bc1gmk9yu
    ]
  end
  let(:valid_addresses) do
    [
      [
        'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
        22, [
          0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
          0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        ]
      ],
      [
        'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
        34, [
          0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
          0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
          0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
          0x62
        ]
      ],
      [
        'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
        42, [
          0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
          0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
          0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
          0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        ]
      ],
      [
        'BC1SW50QA3JX3S',
        4, [
          0x60, 0x02, 0x75, 0x1e
        ]
      ],
      [
        'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
        18, [
          0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
          0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
        ]
      ],
      [
        'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
        34, [
          0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
          0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
          0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
          0x33
        ]
      ]
    ]
  end

  before { Bitcoin.network = :bitcoin }

  describe '#decode / #encode' do
    context 'test vectors' do
      let(:valid_checksums) do
        %w[
          A12UEL5L
          an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs
          abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw
          11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j
          split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w
        ]
      end
      let(:invalid_checksums) do
        [
          ' 1nwldj5',
          "\x7f1axkwrx",
          'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx',
          'pzry9x0s0muk',
          '1pzry9x0s0muk',
          'x1b4n0q5v',
          'li1dgmt3',
          "de1lg7wt\xff"
        ]
      end

      it 'works for valid checksums' do
        valid_checksums.each do |encoded_input|
          human_readable_part, data = Bitcoin::Bech32.decode(encoded_input)
          result = Bitcoin::Bech32.encode(human_readable_part, data)
          expect(result).to eq(encoded_input.downcase)
        end
      end

      it 'returns nil invalid checksums' do
        invalid_checksums.each do |encoded_input|
          human_readable_part, = Bitcoin::Bech32.decode(encoded_input)
          expect(human_readable_part).to be_nil
        end
      end

      it 'works for valid addresses' do
        valid_addresses.each do |encoded_input, _, _|
          human_readable_part, data = Bitcoin::Bech32.decode(encoded_input)
          result = Bitcoin::Bech32.encode(human_readable_part, data)
          expect(result).to eq(encoded_input.downcase)
        end
      end
    end
  end

  describe '#decode_segwit_address / #encode_segwit_address' do
    context 'test vectors' do
      it 'works for valid addresses' do
        valid_addresses.each do |test_address, _, test_script|
          Bitcoin.network = :bitcoin
          version, program = Bitcoin.decode_segwit_address(test_address)

          if version.nil?
            Bitcoin.network = :testnet3
            version, program = Bitcoin.decode_segwit_address(test_address)
          end

          expect(version).not_to be_nil

          script = Bitcoin::Script.to_witness_script(version, program)
          expect(script).to eq(test_script.pack('C*'))

          new_address = Bitcoin.encode_segwit_address(version, program)
          expect(new_address).not_to be_nil
          expect(new_address).to eq(test_address.downcase)
        end
      end

      it 'returns nil for invalid addresses' do
        invalid_addresses.each do |test_address|
          Bitcoin.network = :bitcoin
          version, _program = Bitcoin.decode_segwit_address(test_address)

          if version.nil?
            Bitcoin.network = :testnet3
            version, _program = Bitcoin.decode_segwit_address(test_address)
          end

          expect(version).to be_nil
        end
      end

      it 'returns nil for invalid address encodings' do
        invalid_address_encs.each do |test_hrp, test_version, test_length|
          Bitcoin.network[:bech32_hrp] = test_hrp
          program_hex =
            Array.new(test_length) { 0 }.pack('C*').unpack('H*').first
          new_address = Bitcoin.encode_segwit_address(test_version, program_hex)

          expect(new_address).to be_nil
        end
      end
    end
  end
end
# rubocop:enable Metrics/LineLength
