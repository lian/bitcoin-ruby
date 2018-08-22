# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Protocol::Parser do
  let(:pkt) do
    [
      'f9 be b4 d9', # magic head
      '69 6e 76 00 00 00 00 00 00 00 00 00', # command ('inv')
      '49 00 00 00', # message length
      '11 ea 1c 91', # checksum

      '02', # n hashes
      '01 00 00 00', # type (1=tx)
      'e0 41 c2 38 f7 32 1a 68 0a 34 06 bf fd 72 12 e3 d1 2c b5 12 2a 8c 0b ' \
      '52 76 de 82 30 b1 00 7a 42',
      '01 00 00 00', # type (1=tx)
      '33 00 09 71 a9 70 7b 6c 6d 6e 77 aa 2e ac 43 f3 e5 67 84 cb 61 b2 35 ' \
      'fb 8d fe e0 86 8b 40 7c f3'
    ].map { |s| s.split(' ') }.flatten.join.htb
  end
  let(:handler) { instance_double('Bitcoin::Protocol::Handler') }

  it 'should call appropriate handler' do
    expect(handler)
      .to receive(:on_inv_transaction)
      .and_return([pkt[29..60].reverse])
    expect(handler)
      .to receive(:on_inv_transaction)
      .and_return([pkt[-32..-1].reverse])
    expect(described_class.new(handler).parse(pkt)).to eq('')
  end

  it 'should count total packets and bytes' do
    expect(handler)
      .to receive(:on_inv_transaction)
      .and_return([pkt[29..60].reverse])
    expect(handler)
      .to receive(:on_inv_transaction)
      .and_return([pkt[-32..-1].reverse])

    parser = described_class.new(handler)

    parser.parse pkt
    expect(parser.stats)
      .to eq('total_packets' => 1,
             'total_bytes' => 73,
             'total_errors' => 0,
             'inv' => 1)
  end

  it 'should call error handler for unknown command' do
    expect(handler)
      .to receive(:on_error)
      .with(:unknown_packet, %w[foo 626172])
    expect(described_class.new(handler).process_pkt('foo', 'bar')).to be_nil
  end

  it 'should count total errors' do
    expect(handler)
      .to receive(:on_error)
      .with(:unknown_packet, %w[foo 626172])

    parser = described_class.new(handler)
    parser.process_pkt('foo', 'bar')
    expect(parser.stats['total_errors']).to eq(1)
  end
end
