# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (addr)' do

  it 'parses address packet' do
    pkt = [
      "f9 be b4 d9 61 64 64 72 00 00 00 00 00 00 00 00 1f 00 00 00 e8 b4 c9 ba 01 2b dd d7 4d 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 52 53 de 04 20 8d"
      .split(" ").join].pack("H*")

    class Addr_Handler < Bitcoin::Protocol::Handler
      attr_reader :addr, :err
      def on_addr(addr); (@addr ||= []) << addr; end
      def on_error(*err); (@err ||= []) << err; end
    end

    parser = Bitcoin::Protocol::Parser.new( handler = Addr_Handler.new )
    parser.parse(pkt + "AAAA").should == "AAAA"

    handler.addr.size              .should == 1
    handler.addr.first.alive?      .should == false
    handler.addr.map{|i| i.values }.should == [
      [1305992491, 1, "82.83.222.4", 8333]
    ]
  end

  it "parses broken address packet" do
    pkt = ["01 00 00 00 00".split(" ").join].pack("H*")
    parser = Bitcoin::Protocol::Parser.new( handler = Addr_Handler.new )
    parser.parse_addr(pkt).should == nil
    handler.addr.should == nil
    handler.err.should == [[:addr, pkt[1..-1]]]
  end

end

describe 'Bitcoin::Protocol::Addr' do

  before do
    @pkt = [
      "2b dd d7 4d 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 52 53 de 04 20 8d"
      .split(" ").join].pack("H*")
  end

  it 'parse addr payload' do
    addr = Bitcoin::Protocol::Addr.new(@pkt)
    addr.values.should == [1305992491, 1, "82.83.222.4", 8333]
  end

  it 'initalize time, service and port' do
    Time.freeze do
      addr = Bitcoin::Protocol::Addr.new(nil)
      addr[:time].should == Time.now.to_i
      addr[:service]  .should == 1
      addr[:port]     .should == Bitcoin.network[:default_port]
      addr[:ip]       .should == "127.0.0.1"
    end
  end

  it 'addr payload' do
    addr = Bitcoin::Protocol::Addr.new
    addr[:time] = 1305992491
    addr[:service] = 1
    addr[:ip] = "82.83.222.4"
    addr[:port] = 8333
    addr.to_payload.should == @pkt
    addr.to_payload.bytesize.should == 30
  end


  it 'pack addr packet' do
    addr = Bitcoin::Protocol::Addr.new
    addr[:time] = 1305992491
    addr[:service] = 1
    addr[:ip] = "82.83.222.4"
    addr[:port] = 8333
    Bitcoin::Protocol::Addr.pkt(addr).should ==
      Bitcoin::Protocol.pkt("addr", "\x01" + addr.to_payload)
  end

end
