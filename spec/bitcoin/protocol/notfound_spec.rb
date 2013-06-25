# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (notfound)' do

  class Notfound_Handler < Bitcoin::Protocol::Handler
    attr_reader :notfound
    def on_notfound(type, hash); (@notfound ||= []) << [type, hash.hth]; end
  end

  before do
    @parser = Bitcoin::Protocol::Parser.new( @handler = Notfound_Handler.new )
  end

  it 'parses notfound block message' do
    payload = "\x01\x01\x00\x00\x00:\xE2\x93bDJ\x01\xA9|\xDA>0\x8F\a\xA3L\n\xEF\x0E\xD2\xF2\xC6\xCE\xCA(\xD19}\x80*h+"
    @parser.parse(Bitcoin::Protocol.pkt("notfound", payload) + "AAAA").should == "AAAA"
    @handler.notfound.should == [
      [:tx, "2b682a807d39d128cacec6f2d20eef0a4ca3078f303eda7ca9014a446293e23a"]
    ]
  end

  it 'parses notfound tx message' do
    payload = "\x01\x02\x00\x00\x00:\xE2\x93bDJ\x01\xA9|\xDA>0\x8F\a\xA3L\n\xEF\x0E\xD2\xF2\xC6\xCE\xCA(\xD19}\x80*h+"
    @parser.parse(Bitcoin::Protocol.pkt("notfound", payload) + "AAAA").should == "AAAA"
    @handler.notfound.should == [
      [:block, "2b682a807d39d128cacec6f2d20eef0a4ca3078f303eda7ca9014a446293e23a"]
    ]
  end
end
