require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (version)' do

  it 'parses version' do
    pkt = [
      "f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00 55 00 00 00 40 9c 00 00 01 00 00 00 00 00 00 00 10 42 c9 4e 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 04 d2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 47 9d 4b b8 bb 21 ae d7 f0 71 00 fa 00 00 00"
      .split(" ").join].pack("H*")

    class Version_Handler < Bitcoin::Protocol::Handler
      attr_reader :version, :services, :timestamp, :block
      def on_version(version, services, timestamp, block)
        @version, @services, @timestamp, @block =
          version, services, timestamp, block
      end
    end

    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse(pkt + "AAAA").should == "AAAA"

    handler.version.should == 40000
    handler.services.should == ["01 00 00 00 00 00 00 00".split(' ').join].pack("H*")
    handler.timestamp.should == 1321812496
    handler.block.should == 250
  end

end
