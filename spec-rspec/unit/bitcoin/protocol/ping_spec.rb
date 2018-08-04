# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin::Protocol::Parser (ping/pong)' do
  # Mock handler for ping and pong messages
  class PingHandler < Bitcoin::Protocol::Handler
    attr_reader :nonce

    def on_ping(nonce)
      @nonce = nonce
    end

    def on_pong(nonce)
      @nonce = nonce
    end
  end

  let(:handler) { PingHandler.new }
  let(:parser) { Bitcoin::Protocol::Parser.new(handler) }

  it 'parses ping without nonce' do
    result = parser.parse(
      Bitcoin::Protocol.pkt('ping', '') + 'AAAA'
    )
    expect(result).to eq('AAAA')
    expect(handler.nonce).to be_nil
  end

  it 'parses ping with nonce' do
    result = parser.parse(
      Bitcoin::Protocol.pkt('ping', [12_345].pack('Q')) + 'AAAA'
    )

    expect(result).to eq('AAAA')
    expect(handler.nonce).to eq(12_345)
  end

  it 'builds ping without nonce' do
    parser.parse(Bitcoin::Protocol.ping_pkt)
    expect(handler.nonce).not_to be_nil
  end

  it 'builds ping with nonce' do
    parser.parse(Bitcoin::Protocol.ping_pkt(12_345))
    expect(handler.nonce).to eq(12_345)
  end

  it 'parses pong' do
    result = parser.parse(
      Bitcoin::Protocol.pkt('pong', [12_345].pack('Q')) + 'AAAA'
    )
    expect(result).to eq('AAAA')
    expect(handler.nonce).to eq(12_345)
  end

  it 'builds pong' do
    parser.parse(Bitcoin::Protocol.pong_pkt(12_345))
    expect(handler.nonce).to eq(12_345)
  end
end
