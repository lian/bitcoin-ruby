# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (reject)' do

  it 'parses alert' do
    payload = "\x02tx\x10\bcoinbase\xB5\x93\x84\x8D\x99\xF4\x1AE\xE9\xD2\x90T\x9919\xF0X %\xBBE\x19\x19\x86\xBC\r\x812\x7F\xC4\xEDN"

    alert = Bitcoin::Protocol::Reject.parse(payload)
    alert.message.should == "tx"
    alert.ccode.should == :invalid
    alert.reason.should == "coinbase"
    alert.tx_hash.should == "4eedc47f32810dbc86191945bb252058f03931995490d2e9451af4998d8493b5"
  end

end
