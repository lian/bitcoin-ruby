# encoding: ascii-8bit

require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (alert)' do

  it 'parses alert' do
    payload = "s\x01\x00\x00\x007f@O\x00\x00\x00\x00\xB3\x05CO\x00\x00\x00\x00\xF2\x03\x00\x00\xF1\x03\x00\x00\x00\x10'\x00\x00H\xEE\x00\x00\x00d\x00\x00\x00\x00FSee bitcoin.org/feb20 if you have trouble connecting after 20 February\x00G0E\x02!\x00\x83\x89\xDFE\xF0p?9\xEC\x8C\x1C\xC4,\x13\x81\x0F\xFC\xAE\x14\x99[\xB6H4\x02\x19\xE3S\xB6;S\xEB\x02 \t\xECe\xE1\xC1\xAA\xEE\xC1\xFD3LkhK\xDE+?W0`\xD5\xB7\f:Fr3&\xE4\xE8\xA4\xF1"

    alert = Bitcoin::Protocol::Alert.parse(payload)
    alert.values.should == [1, 1329620535, 1329792435, 1010, 1009, nil, 10000, 61000, nil, 100, nil, "See bitcoin.org/feb20 if you have trouble connecting after 20 February", nil]
    alert.valid_signature?.should == true


    payload = "\xAC\x01\x00\x00\x00o\xF2cO\x00\x00\x00\x00k\"EQ\x00\x00\x00\x00\xF4\x03\x00\x00\xF2\x03\x00\x00\x00`\xEA\x00\x00`\xEA\x00\x00\x03\x11/Satoshi:0.6.0.3/\x0F/Satoshi:0.6.0/\x12/bitcoin-qt:0.6.0/\x88\x13\x00\x00\x00JURGENT: security fix for Bitcoin-Qt on Windows: http://bitcoin.org/critfix\x00H0F\x02!\x00\xB7\xB1o\x86\x0F\x9EZ\x87bt\xAE\xB7$u\xD2\xDE\xC3\x86j\xA7\xAF\x82\xAD\x97\\\x83Qd\xA9\x97\xA7\x16\x02!\x00\x86\xB4\x18)\xCB\x84\xBE\xD2\x86\x10\x82G\xBE\xBF;\xE9{\xD9\xB3\x1E\xB4/g\xB4\xD33\xCE\x8B\x1D}\xF8^"

    alert = Bitcoin::Protocol::Alert.parse(payload)
    alert.values.should == [1, 1331950191, 1363485291, 1012, 1010, nil, 60000, 60000, ["/Satoshi:0.6.0.3/", "/Satoshi:0.6.0/", "/bitcoin-qt:0.6.0/"], 5000, nil, "URGENT: security fix for Bitcoin-Qt on Windows: http://bitcoin.org/critfix", nil]
    alert.valid_signature?.should == true
  end

end
