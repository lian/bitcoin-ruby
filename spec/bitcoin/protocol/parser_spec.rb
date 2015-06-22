# encoding: ascii-8bit

require_relative '../spec_helper.rb'
require 'minitest/mock'

include Bitcoin::Protocol

describe 'Bitcoin::Protocol::Parser' do


  before {
    @pkt= [
        "f9 be b4 d9", # magic head
        "69 6e 76 00 00 00 00 00 00 00 00 00", # command ("inv")
        "49 00 00 00", # message length
        "11 ea 1c 91", # checksum

        "02", # n hashes
        "01 00 00 00", # type (1=tx)
        "e0 41 c2 38 f7 32 1a 68 0a 34 06 bf fd 72 12 e3 d1 2c b5 12 2a 8c 0b 52 76 de 82 30 b1 00 7a 42",
        "01 00 00 00", # type (1=tx)
        "33 00 09 71 a9 70 7b 6c 6d 6e 77 aa 2e ac 43 f3 e5 67 84 cb 61 b2 35 fb 8d fe e0 86 8b 40 7c f3"
      ].map{|s| s.split(" ")}.flatten.join.htb
    @handler = MiniTest::Mock.new }
  after { @handler.verify }

  it 'should call appropriate handler' do
    @handler.expect(:on_inv_transaction, nil, [@pkt[29..60].reverse])
    @handler.expect(:on_inv_transaction, nil, [@pkt[-32..-1].reverse])
    Parser.new( @handler ).parse( @pkt ).should == ""
  end

  it 'should count total packets and bytes' do
    parser = Parser.new
    parser.parse @pkt
    parser.stats.should == {"total_packets"=>1, "total_bytes"=>73, "total_errors" => 0, "inv"=>1}
  end

  it 'should call error handler for unknown command' do
    @handler.expect(:on_error, nil, [:unknown_packet, ["foo", "626172"]])
    Parser.new( @handler ).process_pkt('foo', "bar").should == nil
  end

  it 'should count total errors' do
    parser = Parser.new
    parser.process_pkt('foo', 'bar')
    parser.stats['total_errors'].should == 1
  end

end
