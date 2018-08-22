# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin.network' do
  describe 'bitcoin network' do
    it 'returns the expected network descriptors' do
      Bitcoin.network = :bitcoin

      expect(Bitcoin.network[:magic_head]).to eq(['F9BEB4D9'].pack('H*'))
      expect(Bitcoin.network[:address_version]).to eq('00')
      expect(Bitcoin.network[:genesis_hash])
        .to eq('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
    end

    it 'can be set to mainnet' do
      Bitcoin.network = :bitcoin

      expect(Bitcoin.network).to eq(Bitcoin::NETWORKS[:bitcoin])
    end
  end

  describe 'magic head' do
    # Handler used in tests to expose additional information.
    class TestHandler
      attr_reader :inv

      def on_inv_transaction(inv)
        @inv = inv
      end
    end

    it 'uses the correct one for message parsing' do
      pkt = [
        'f9 be b4 d9 69 6e 76 00 00 00 00 00 00 00 00 00 49 00 00 00 11 ea ' \
        '1c 91 02 01 00 00 00 e0 41 c2 38 f7 32 1a 68 0a 34 06 bf fd 72 12 ' \
        'e3 d1 2c b5 12 2a 8c 0b 52 76 de 82 30 b1 00 7a 42 01 00 00 00 33 ' \
        '00 09 71 a9 70 7b 6c 6d 6e 77 aa 2e ac 43 f3 e5 67 84 cb 61 b2 35 ' \
        'fb 8d fe e0 86 8b 40 7c f3'.split(' ').join
      ].pack('H*')

      handler1 = TestHandler.new
      handler2 = TestHandler.new
      parser1 = Bitcoin::Protocol::Parser.new(handler1)
      parser2 = Bitcoin::Protocol::Parser.new(handler2)

      Bitcoin.network = :testnet
      expect(parser2)
        .to receive(:handle_stream_error).with(:close, 'head_magic not found')
      expect(parser2.parse(pkt)).to be_empty
      expect(handler2.inv).to be_nil

      Bitcoin.network = :bitcoin
      expected_packet = [
        'f37c408b86e0fe8dfb35b261cb8467e5f343ac2eaa776e6d6c7b70a971090033'
      ].pack('H*')
      expect(parser1.parse(pkt)).to be_empty
      expect(handler1.inv).to eq(expected_packet)
    end

    it 'uses the correct one for packet creation' do
      Bitcoin.network = :testnet
      expect(Bitcoin::Protocol.pkt('foo', 'bar')[0...4])
        .to eq(['FABFB5DA'].pack('H*'))

      Bitcoin.network = :bitcoin
      expect(Bitcoin::Protocol.pkt('foo', 'bar')[0...4])
        .to eq(['F9BEB4D9'].pack('H*'))
    end
  end
end
