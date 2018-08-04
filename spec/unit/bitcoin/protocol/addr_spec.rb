# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin::Protocol::Parser (addr)' do
  # Mock protocl handler
  class AddrHandler < Bitcoin::Protocol::Handler
    attr_reader :addr, :err, :pkt

    def on_addr(addr)
      (@addr ||= []) << addr
    end

    def on_error(*err)
      (@err ||= []) << err
    end
  end

  it 'parses address packet' do
    pkt = [
      'f9 be b4 d9 61 64 64 72 00 00 00 00 00 00 00 00 1f 00 00 00 e8 b4 c9 ' \
      'ba 01 2b dd d7 4d 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ' \
      '00 ff ff 52 53 de 04 20 8d'.split(' ').join
    ].pack('H*')

    handler = AddrHandler.new
    parser = Bitcoin::Protocol::Parser.new(handler)
    expect(parser.parse(pkt + 'AAAA')).to eq('AAAA')

    expect(handler.addr.size).to eq(1)
    expect(handler.addr.first.alive?).to be false
    expect(handler.addr.map(&:values)).to eq(
      [[1_305_992_491, 1, '82.83.222.4', 8_333]]
    )
  end

  it 'parses broken address packet' do
    pkt = ['01 00 00 00 00'.split(' ').join].pack('H*')
    handler = AddrHandler.new
    parser = Bitcoin::Protocol::Parser.new(handler)
    expect(parser.parse_addr(pkt)).to be_nil
    expect(handler.addr).to be_nil
    expect(handler.err).to eq([[:addr, pkt[1..-1]]])
  end
end

describe Bitcoin::Protocol::Addr do
  let(:pkt) do
    [
      '2b dd d7 4d 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ' \
      'ff 52 53 de 04 20 8d'.split(' ').join
    ].pack('H*')
  end

  it 'parse addr payload' do
    addr = Bitcoin::Protocol::Addr.new(pkt)
    expect(addr.values).to eq([1_305_992_491, 1, '82.83.222.4', 8_333])
  end

  it 'initalize time, service and port' do
    Time.freeze do
      addr = Bitcoin::Protocol::Addr.new(nil)
      expect(addr[:time]).to eq(Time.now.to_i)
      expect(addr[:service]).to eq(1)
      expect(addr[:port]).to eq(Bitcoin.network[:default_port])
      expect(addr[:ip]).to eq('127.0.0.1')
    end
  end

  it 'addr payload' do
    addr = Bitcoin::Protocol::Addr.new
    addr[:time] = 1_305_992_491
    addr[:service] = 1
    addr[:ip] = '82.83.222.4'
    addr[:port] = 8_333
    expect(addr.to_payload).to eq(pkt)
    expect(addr.to_payload.bytesize).to eq(30)
  end

  it 'pack addr packet' do
    addr = Bitcoin::Protocol::Addr.new
    addr[:time] = 1_305_992_491
    addr[:service] = 1
    addr[:ip] = '82.83.222.4'
    addr[:port] = 8_333
    expect(Bitcoin::Protocol::Addr.pkt(addr))
      .to eq(Bitcoin::Protocol.pkt('addr', "\x01" + addr.to_payload))
  end
end
