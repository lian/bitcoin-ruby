# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (ping/pong)' do

  class Ping_Handler < Bitcoin::Protocol::Handler
    attr_reader :nonce
    def on_ping(nonce)
      @nonce = nonce
    end
    def on_pong(nonce)
      @nonce = nonce
    end
  end

  before do
    @parser = Bitcoin::Protocol::Parser.new( @handler = Ping_Handler.new )
  end

  it 'parses ping without nonce' do
    @parser.parse(Bitcoin::Protocol.pkt("ping", "") + "AAAA").should == "AAAA"
    @handler.nonce.should == nil
  end

  it 'parses ping with nonce' do
    @parser.parse(Bitcoin::Protocol.pkt("ping", [12345].pack("Q")) + "AAAA").should == "AAAA"
    @handler.nonce.should == 12345
  end

  it 'builds ping without nonce' do
    @parser.parse(Bitcoin::Protocol::ping_pkt)
    @handler.nonce.should != nil
  end

  it 'builds ping with nonce' do
    @parser.parse(Bitcoin::Protocol::ping_pkt(12345))
    @handler.nonce.should == 12345
  end

  it 'parses pong' do
    @parser.parse(Bitcoin::Protocol.pkt("pong", [12345].pack("Q")) + "AAAA").should == "AAAA"
    @handler.nonce.should == 12345
  end

  it 'builds pong' do
    @parser.parse(Bitcoin::Protocol::pong_pkt(12345))
    @handler.nonce.should == 12345
  end

end
