require_relative 'spec_helper.rb'
require 'bitcoin/script'

describe 'Bitcoin::Script' do
  @script = [
    ["410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"].pack("H*"),
    ["47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"].pack("H*")
  ]

  it '#to_string' do
    Bitcoin::Script.new(@script[0]).to_string.should ==
      "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3 OP_CHECKSIG"

    Bitcoin::Script.new(@script[1]).to_string.should ==
      "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"
  end

  it 'Script#binary_from_string' do
    str = Bitcoin::Script.new(@script[0]).to_string
    Bitcoin::Script.binary_from_string(str).unpack("H*")[0].should == @script[0].unpack("H*")[0]
    Bitcoin::Script.new(Bitcoin::Script.binary_from_string(str)).to_string.should == str

    str = Bitcoin::Script.new(@script[1]).to_string
    Bitcoin::Script.binary_from_string(str).unpack("H*")[0].should == @script[1].unpack("H*")[0]
    Bitcoin::Script.new(Bitcoin::Script.binary_from_string(str)).to_string.should == str
    # TODO make tests for OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 cases
  end

  it '#get_pubkey' do
    Bitcoin::Script.new(@script[0]).get_pubkey.should ==
      "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
  end

  it '#get_pubkey_address' do
    Bitcoin::Script.new(@script[0]).get_pubkey_address.should ==
      "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"
  end

  it '#is_send_to_ip?' do
    Bitcoin::Script.new(@script[0]).is_send_to_ip?.should == true
    Bitcoin::Script.new(@script[1]).is_send_to_ip?.should == false
  end

  it '#run' do
    script = @script[1] + @script[0]
    Bitcoin::Script.new(script).run.should == true
    # TODO test more scripts
  end
end
