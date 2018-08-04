# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin::Protocol::Parser (version)' do
  # Mock interface
  class VersionHandler < Bitcoin::Protocol::Handler
    attr_reader :pkt

    def on_version(pkt)
      @pkt = pkt
    end
  end

  let(:handler) { VersionHandler.new }

  it 'parses version packets' do
    pkt = Bitcoin::Protocol.pkt(
      'version',
      [
        '60ea00000100000000000000b3c1424f00000000010000000000000000000000000' \
        '000000000ffff7f000001e1ca010000000000000000000000000000000000ffff7f' \
        '000001479d9525d0c7b30688ae122f626974636f696e2d71743a302e362e302f82b' \
        '60000'
      ].pack('H*')
    )

    parser = Bitcoin::Protocol::Parser.new(handler)
    expect(parser.parse(pkt + 'AAAA')).to eq('AAAA')

    pkt = handler.pkt
    expect(pkt.fields)
      .to eq(version: 60_000,
             services: Bitcoin::Protocol::Version::NODE_NETWORK,
             time: 1_329_775_027,
             from: '127.0.0.1:18333',
             to: '127.0.0.1:57802',
             nonce: 12_576_309_328_653_329_813,
             user_agent: '/bitcoin-qt:0.6.0/',
             last_block: 46_722,
             relay: true)

    pkt = [
      'f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00 55 00 00 00 a4 c2 08 ' \
      'cb 40 9c 00 00 01 00 00 00 00 00 00 00 10 42 c9 4e 00 00 00 00 01 00 ' \
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 04 ' \
      'd2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 ' \
      '00 01 47 9d 4b b8 bb 21 ae d7 f0 71 00 fa 00 00 00'.split(' ').join
    ].pack('H*')

    handler = VersionHandler.new
    parser = Bitcoin::Protocol::Parser.new(handler)
    expect(parser.parse(pkt + 'AAAA')).to eq('AAAA')

    pkt = handler.pkt
    expect(pkt.fields)
      .to eq(version: 40_000,
             services: Bitcoin::Protocol::Version::NODE_NETWORK,
             time: 1_321_812_496,
             from: '127.0.0.1:18333',
             to: '127.0.0.1:1234',
             nonce: 8_210_299_263_586_646_091,
             user_agent: '',
             last_block: 250,
             relay: true)
  end

  it 'creates version packets' do
    version = Bitcoin::Protocol::Version.new(
      time: 1_337,
      from: '127.0.0.1:8333',
      to: '127.0.0.1:1234',
      nonce: 123,
      last_block: 188_617
    )

    handler = VersionHandler.new
    parser = Bitcoin::Protocol::Parser.new(handler)
    parser.parse(version.to_pkt)

    pkt = handler.pkt
    expect(pkt.fields)
      .to eq(version: Bitcoin.network[:protocol_version],
             services: Bitcoin::Protocol::Version::NODE_NETWORK,
             time: 1_337,
             to: '127.0.0.1:8333',
             from: '127.0.0.1:1234',
             nonce: 123,
             user_agent: "/bitcoin-ruby:#{Bitcoin::VERSION}/",
             last_block: 188_617,
             relay: true)
  end

  # check that we support sending and receiving of the BIP0037 fRelay flag
  it 'creates spv enabled version packets' do
    version = Bitcoin::Protocol::Version.new(
      time: 1_337,
      from: '127.0.0.1:8333',
      to: '127.0.0.1:1234',
      nonce: 123,
      last_block: 188_617,
      relay: false
    )

    parser = Bitcoin::Protocol::Parser.new(handler)
    parser.parse(version.to_pkt)

    pkt = handler.pkt
    expect(pkt.fields)
      .to eq(version: Bitcoin.network[:protocol_version],
             services: Bitcoin::Protocol::Version::NODE_NETWORK,
             time: 1_337,
             to: '127.0.0.1:8333',
             from: '127.0.0.1:1234',
             nonce: 123,
             user_agent: "/bitcoin-ruby:#{Bitcoin::VERSION}/",
             last_block: 188_617,
             relay: false)
  end
end
