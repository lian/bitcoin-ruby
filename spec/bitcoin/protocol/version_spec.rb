require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (version)' do

  class Version_Handler < Bitcoin::Protocol::Handler
    attr_reader :pkt
    def on_version(pkt)
      @pkt = pkt
    end
  end

  it 'parses version' do
    pkt = Bitcoin::Protocol.pkt("version",
      ["60ea00000100000000000000b3c1424f00000000010000000000000000000000000000000000ffff7f000001e1ca010000000000000000000000000000000000ffff7f000001479d9525d0c7b30688ae122f626974636f696e2d71743a302e362e302f82b60000"].pack("H*"))

    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse(pkt + "AAAA").should == "AAAA"

    pkt = handler.pkt
    pkt.version.should == 60000
    pkt.services.should == ["01 00 00 00 00 00 00 00".split(' ').join].pack("H*")
    pkt.timestamp.should == 1329775027
    pkt.block.should == 46722
    pkt.from.should == { :service => 1, :ip => [127, 0, 0, 1], :port => 18333 }
    pkt.to.should   == { :service => 1, :ip => [127, 0, 0, 1], :port => 57802 }
    pkt.user_agent.should == "/bitcoin-qt:0.6.0/"
  end

  it 'parses version' do
    pkt = [
      "f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00 55 00 00 00 a4 c2 08 cb 40 9c 00 00 01 00 00 00 00 00 00 00 10 42 c9 4e 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 04 d2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 47 9d 4b b8 bb 21 ae d7 f0 71 00 fa 00 00 00"
        .split(" ").join].pack("H*")


    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse(pkt + "AAAA").should == "AAAA"

    pkt = handler.pkt
    pkt.version.should == 40000
    pkt.services.should == ["01 00 00 00 00 00 00 00".split(' ').join].pack("H*")
    pkt.timestamp.should == 1321812496
    pkt.block.should == 250
    pkt.from.should == { :service => 1, :ip => [127, 0, 0, 1], :port => 18333 }
    pkt.to.should   == { :service => 1, :ip => [127, 0, 0, 1], :port => 1234 }
  end

  it 'builds version' do
    id, block = Bitcoin::Protocol::Uniq, 12345
    from, to = "127.0.0.1:18333", "127.0.0.1:1234"
    pkt = Bitcoin::Protocol::VersionPkt.build_payload(id, from, to, block)
    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse(Bitcoin::Protocol.pkt("version", pkt))

    pkt = handler.pkt
    pkt.version.should == Bitcoin::Protocol::VERSION
    pkt.services.should == "\x01\x00\x00\x00\x00\x00\x00\x00"
    Time.at(pkt.timestamp).should <= Time.now
    pkt.to.should == {:service=>1, :ip=>[127, 0, 0, 1], :port=>18333}
    pkt.from.should == {:service=>1, :ip=>[127, 0, 0, 1], :port=>1234}
    pkt.block.should == 12345
    pkt.user_agent.should == "/bitcoin-ruby:#{Bitcoin::VERSION}/"
  end

end
