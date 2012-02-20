require_relative '../spec_helper.rb'

describe 'Bitcoin::Protocol::Parser (alert)' do

  it 'parses alert' do
    payload = "s\x01\x00\x00\x007f@O\x00\x00\x00\x00\xB3\x05CO\x00\x00\x00\x00\xF2\x03\x00\x00\xF1\x03\x00\x00\x00\x10'\x00\x00H\xEE\x00\x00\x00d\x00\x00\x00\x00FSee bitcoin.org/feb20 if you have trouble connecting after 20 February\x00G0E\x02!\x00\x83\x89\xDFE\xF0p?9\xEC\x8C\x1C\xC4,\x13\x81\x0F\xFC\xAE\x14\x99[\xB6H4\x02\x19\xE3S\xB6;S\xEB\x02 \t\xECe\xE1\xC1\xAA\xEE\xC1\xFD3LkhK\xDE+?W0`\xD5\xB7\f:Fr3&\xE4\xE8\xA4\xF1"

    alert = Bitcoin::Protocol::Alert.parse(payload)
    alert.values.should == [1, 1329620535, 1329792435, 1010, 1009, nil, 10000, 61000, nil, 100, nil, "See bitcoin.org/feb20 if you have trouble connecting after 20 February", nil]
    alert.valid_signature?.should == true
  end

end
