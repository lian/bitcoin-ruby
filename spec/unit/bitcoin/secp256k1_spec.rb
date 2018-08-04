# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Secp256k1 do
  let(:fixture_text) { 'bitcoin-ruby-test-data' }

  describe '#generate_key_pair' do
    it 'generates a compressed key pair' do
      private_key, public_key =
        Bitcoin::Secp256k1.generate_key_pair(true)

      expect(private_key.bytesize).to eq(32)
      expect(public_key.bytesize).to eq(33)
      expect(["\x03", "\x02"]).to include(public_key[0])
    end

    it 'generates an uncompressed key pair' do
      private_key, public_key =
        Bitcoin::Secp256k1.generate_key_pair(false)

      expect(private_key.bytesize).to eq(32)
      expect(public_key.bytesize).to eq(65)
      expect(public_key[0]).to eq("\x04")
    end
  end

  describe '#generate_key' do
    it 'generates a compressed key' do
      key = Bitcoin::Secp256k1.generate_key(true)
      expect(key.compressed).to be true
    end

    it 'generates an uncompressed key' do
      key = Bitcoin::Secp256k1.generate_key(false)
      expect(key.compressed).to be false
    end
  end

  describe '#sign' do
    it 'successfully signs and verifies text' do
      private_key, public_key = Bitcoin::Secp256k1.generate_key_pair
      signature = Bitcoin::Secp256k1.sign(fixture_text, private_key)

      expect(
        Bitcoin::Secp256k1.verify(fixture_text, signature, public_key)
      ).to be true
      expect(
        Bitcoin::Secp256k1.verify(fixture_text.upcase, signature, public_key)
      ).to be false
    end

    it 'supports RFC6979 deterministic signatures' do
      private_key, = Bitcoin::Secp256k1.generate_key_pair
      first  = Bitcoin::Secp256k1.sign(fixture_text, private_key)
      second = Bitcoin::Secp256k1.sign(fixture_text, private_key)
      expect(first).to eq(second)

      private_key, = Bitcoin::Secp256k1.generate_key_pair
      second = Bitcoin::Secp256k1.sign(fixture_text, private_key)
      expect(first).not_to eq(second)
    end
  end

  describe '#sign_compact' do
    it 'signs and recovers with compressed keys' do
      private_key, public_key = Bitcoin::Secp256k1.generate_key_pair(true)

      signature = Bitcoin::Secp256k1.sign_compact(
        fixture_text, private_key, true
      )
      expect(signature.bytesize).to eq(65)

      recovered_public_key = Bitcoin::Secp256k1.recover_compact(
        fixture_text, signature
      )
      expect(recovered_public_key.bytesize).to eq(33)
      expect(recovered_public_key).to eq(public_key)
    end

    it 'signs and recovers with uncompressed keys' do
      private_key, public_key = Bitcoin::Secp256k1.generate_key_pair(false)
      signature = Bitcoin::Secp256k1.sign_compact(
        fixture_text, private_key, false
      )
      expect(signature.bytesize).to eq(65)

      recovered_public_key = Bitcoin::Secp256k1.recover_compact(
        fixture_text, signature
      )

      expect(recovered_public_key.bytesize).to eq(65)
      expect(recovered_public_key).to eq(public_key)
    end

    context 'when compared to OpenSSL' do
      let(:message) { 'hello world' }

      it 'has matching signing and recovery results' do
        key = Bitcoin::Key.new(
          '82a0c421a0f67c7a88a329b2c15f2849aa1c8cfa9c9a6513f056f80ee8eaacc4',
          nil,
          false
        )

        expect(key.pub)
          .to eq('0490b0854581a291b83c1945775f156da22445df99e445581321ac3aa62' \
                 '535ff369334316dfd157acc7bb2e4d3eb85951f6d1b7f62f6f60a09e0db' \
                 'd5c87d3ffae9')

        private_key_binary = [key.priv].pack('H*')

        openssl_signature = Bitcoin::OpenSSL_EC.sign_compact(
          message, private_key_binary, nil, false
        )
        libsecp_signature = Bitcoin::Secp256k1.sign_compact(
          message, private_key_binary, false
        )

        expect(
          Bitcoin::OpenSSL_EC.recover_compact(message, openssl_signature)
        ).to eq(key.pub)
        expect(
          Bitcoin::Secp256k1.recover_compact(message, openssl_signature)
            .unpack('H*')[0]
        ).to eq(key.pub)

        expect(
          Bitcoin::OpenSSL_EC.recover_compact(message, libsecp_signature)
        ).to eq(key.pub)
        expect(
          Bitcoin::Secp256k1.recover_compact(message, libsecp_signature)
            .unpack('H*')[0]
        ).to eq(key.pub)
      end
    end
  end
end
