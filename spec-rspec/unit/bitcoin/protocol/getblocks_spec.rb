# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin::Protocol::Parser (getblocks)' do
  # Mock handler interface
  class GetblocksHandler < Bitcoin::Protocol::Handler
    attr_reader :version, :locator, :stop_hash

    def on_getblocks(version, locator, stop_hash)
      @version = version
      @locator = locator
      @stop_hash = stop_hash
    end
  end

  let(:handler) { GetblocksHandler.new }
  let(:parser) { Bitcoin::Protocol::Parser.new(handler) }
  let(:pkt) do
    'f9beb4d9676574626c6f636b7300000065000000b3b7ad6e71110100026fe28c0ab6f1b3' \
    '72c1a6a246ae63f74f931e8365e15a089c68d61900000000006fe28c0ab6f1b372c1a6a2' \
    '46ae63f74f931e8365e15a089c68d6190000000000000000000000000000000000000000' \
    '0000000000000000000000000000000000'.htb
  end

  it 'parses getblocks' do
    expect(parser.parse(pkt + 'AAAA')).to eq('AAAA')
    expect(handler.version).to eq(70_001)
    expect(handler.locator).to eq(
      %w[
        000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
      ]
    )
    expect(handler.stop_hash).to eq('00' * 32)
  end

  it 'builds getblocks' do
    parser.parse(pkt + 'AAAA')
    expect(Bitcoin::Protocol.getblocks_pkt(70_001, handler.locator).hth)
      .to eq(pkt.hth)
  end
end
