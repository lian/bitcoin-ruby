# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin::Protocol::Parser (notfound)' do
  # Mock handler
  class NotfoundHandler < Bitcoin::Protocol::Handler
    attr_reader :notfound

    def on_notfound(type, hash)
      (@notfound ||= []) << [type, hash.hth]
    end
  end

  let(:handler) { NotfoundHandler.new }
  let(:parser) { Bitcoin::Protocol::Parser.new(handler) }

  it 'parses notfound block message' do
    payload = "\x01\x01\x00\x00\x00:\xE2\x93bDJ\x01\xA9|\xDA>0\x8F\a\xA3L\n" \
              "\xEF\x0E\xD2\xF2\xC6\xCE\xCA(\xD19}\x80*h+"
    expect(
      parser.parse(Bitcoin::Protocol.pkt('notfound', payload) + 'AAAA')
    ).to eq('AAAA')
    expect(handler.notfound).to eq(
      [
        [:tx, '2b682a807d39d128cacec6f2d20eef0a4ca3078f303eda7ca9014a446293e23a']
      ]
    )
  end

  it 'parses notfound tx message' do
    payload = "\x01\x02\x00\x00\x00:\xE2\x93bDJ\x01\xA9|\xDA>0\x8F\a\xA3L\n" \
              "\xEF\x0E\xD2\xF2\xC6\xCE\xCA(\xD19}\x80*h+"
    expect(
      parser.parse(Bitcoin::Protocol.pkt('notfound', payload) + 'AAAA')
    ).to eq('AAAA')
    expect(handler.notfound).to eq(
      [
        [:block, '2b682a807d39d128cacec6f2d20eef0a4ca3078f303eda7ca9014a446293e23a']
      ]
    )
  end
end
