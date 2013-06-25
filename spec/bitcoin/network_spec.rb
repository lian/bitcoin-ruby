# encoding: ascii-8bit

require_relative 'spec_helper.rb'

describe 'Bitcoin::network' do

  it 'returns network descriptor' do
    Bitcoin.network = :bitcoin
    net = Bitcoin::network
    net[:magic_head].should == "\xF9\xBE\xB4\xD9"
    net[:address_version].should == "00"
    net[:genesis_hash].should == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  end

  it 'can be set to main net' do
    Bitcoin::network = :bitcoin
    Bitcoin::network.should == Bitcoin::NETWORKS[:bitcoin]
  end

  class Test_Handler
    attr_reader :inv
    def on_inv_transaction inv
      @inv = inv
    end
  end

  it 'uses correct magic_head when parsing a message' do
    pkt = ["f9 be b4 d9 69 6e 76 00 00 00 00 00 00 00 00 00 49 00 00 00 11 ea 1c 91 02 01 00 00 00 e0 41 c2 38 f7 32 1a 68 0a 34 06 bf fd 72 12 e3 d1 2c b5 12 2a 8c 0b 52 76 de 82 30 b1 00 7a 42 01 00 00 00 33 00 09 71 a9 70 7b 6c 6d 6e 77 aa 2e ac 43 f3 e5 67 84 cb 61 b2 35 fb 8d fe e0 86 8b 40 7c f3".split(" ").join].pack("H*")

    parser1 = Bitcoin::Protocol::Parser.new(handler1 = Test_Handler.new)
    parser2 = Bitcoin::Protocol::Parser.new(handler2 = Test_Handler.new)

    Bitcoin::network = :testnet
    parser2.parse(pkt).should == ""
    handler2.inv.should == nil

    Bitcoin::network = :bitcoin
    parser1.parse(pkt).should == ''
    handler1.inv.should == ["f37c408b86e0fe8dfb35b261cb8467e5f343ac2eaa776e6d6c7b70a971090033"].pack("H*")
  end

  it 'uses correct magic head when creating a message' do
    Bitcoin::network = :testnet
    Bitcoin::Protocol.pkt('foo', "bar")[0...4].should == "\xFA\xBF\xB5\xDA"

    Bitcoin::network = :bitcoin
    Bitcoin::Protocol.pkt('foo', "bar")[0...4].should == "\xF9\xBE\xB4\xD9"
  end

end
