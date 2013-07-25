# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (version)' do

  class Version_Handler < Bitcoin::Protocol::Handler
    attr_reader :pkt
    def on_version(pkt)
      @pkt = pkt
    end
  end

  it 'parses version packets' do
    pkt = Bitcoin::Protocol.pkt("version",
      ["60ea00000100000000000000b3c1424f00000000010000000000000000000000000000000000ffff7f000001e1ca010000000000000000000000000000000000ffff7f000001479d9525d0c7b30688ae122f626974636f696e2d71743a302e362e302f82b60000"].pack("H*"))

    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse(pkt + "AAAA").should == "AAAA"

    pkt = handler.pkt
    pkt.fields.should == {
      :version     => 60000,
      :services    => Bitcoin::Protocol::Version::NODE_NETWORK,
      :time        => 1329775027,
      :from        => "127.0.0.1:18333",
      :to          => "127.0.0.1:57802",
      :nonce       => 12576309328653329813,
      :user_agent  => "/bitcoin-qt:0.6.0/",
      :last_block  => 46722
    }

    pkt = [
      "f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00 55 00 00 00 a4 c2 08 cb 40 9c 00 00 01 00 00 00 00 00 00 00 10 42 c9 4e 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 04 d2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 7f 00 00 01 47 9d 4b b8 bb 21 ae d7 f0 71 00 fa 00 00 00"
        .split(" ").join].pack("H*")


    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse(pkt + "AAAA").should == "AAAA"

    pkt = handler.pkt
    pkt.fields.should == {
      :version     => 40000,
      :services    => Bitcoin::Protocol::Version::NODE_NETWORK,
      :time        => 1321812496,
      :from        => "127.0.0.1:18333",
      :to          => "127.0.0.1:1234",
      :nonce       => 8210299263586646091,
      :user_agent  => '',
      :last_block  => 250
    }
  end

  it 'creates version packets' do
    version = Bitcoin::Protocol::Version.new({
      :time       => 1337,
      :from       => "127.0.0.1:8333",
      :to         => "127.0.0.1:1234",
      :nonce      => 123,
      :last_block => 188617,
    })

    parser = Bitcoin::Protocol::Parser.new( handler = Version_Handler.new )
    parser.parse( version.to_pkt )

    pkt = handler.pkt
    pkt.fields.should == {
      :version    => Bitcoin.network[:protocol_version],
      :services   => Bitcoin::Protocol::Version::NODE_NETWORK,
      :time       => 1337,
      :to         => "127.0.0.1:8333",
      :from       => "127.0.0.1:1234",
      :nonce      => 123,
      :user_agent => "/bitcoin-ruby:#{Bitcoin::VERSION}/",
      :last_block => 188617
    }
  end

end
