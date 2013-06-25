# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (getblocks)' do

  class Getblocks_Handler < Bitcoin::Protocol::Handler
    attr_reader :version, :locator, :stop_hash
    def on_getblocks(version, locator, stop_hash)
      @version, @locator, @stop_hash = version, locator, stop_hash
    end
  end

  before do
    @parser = Bitcoin::Protocol::Parser.new( @handler = Getblocks_Handler.new )
    @pkt = "f9beb4d9676574626c6f636b7300000065000000b3b7ad6e71110100026fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000000000000000000000000000000000000000000000000000000000".htb
    @parser.parse(@pkt + "AAAA").should == "AAAA"
  end

  it 'parses getblocks' do
    @handler.version.should == 70001
    @handler.locator.should == [
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" ]
    @handler.stop_hash.should == "00"*32
  end

  it 'builds getblocks' do
    Bitcoin::Protocol.getblocks_pkt(70001, @handler.locator).hth.should == @pkt.hth
  end

end
