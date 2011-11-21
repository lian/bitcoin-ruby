require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (version)' do

  it 'parses version' do
    pkt = [
      "f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00 55 00 00 00 40 9c 00 00 01 00 00 00 00 00 00 00 10 42 c9 4e 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 04 d2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 47 9d 4b b8 bb 21 ae d7 f0 71 00 fa 00 00 00"
      .split(" ").join].pack("H*")

    class Version_Handler < Bitcoin::Protocol::Handler
      attr_reader :pkt
      def on_version(pkt)
        @pkt = pkt
      end
    end

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

end
