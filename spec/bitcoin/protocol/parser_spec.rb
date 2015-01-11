# encoding: ascii-8bit

require_relative '../spec_helper.rb'

require 'minitest/mock'

describe 'Bitcoin::Protocol::Parser' do

  before { @handler = MiniTest::Mock.new }
  after { @handler.verify }

  it 'should call appropriate handler' do
    pkt = [
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

    @handler.expect(:on_inv_transaction, nil, [pkt[29..60].reverse])
    @handler.expect(:on_inv_transaction, nil, [pkt[-32..-1].reverse])
    Bitcoin::Protocol::Parser.new( @handler ).parse(pkt).should == ""
  end

  it 'should call error handler for unknown command' do
    pkt = ("f9 be b4 d9 66 6f 6f" + " 00"*32).split(" ").join.htb
    @handler.expect(:on_error, nil, [:unknown_packet, ["foo", "bar"]])
    Bitcoin::Protocol::Parser.new( @handler ).process_pkt('foo', "bar").should == nil
  end

end
