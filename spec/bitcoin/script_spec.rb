require_relative 'spec_helper.rb'
require 'bitcoin/script'

describe 'Bitcoin::Script' do
  @script = [
    ["410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"].pack("H*"),
    ["47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"].pack("H*"),
    ["76a91417977bca1b6287a5e6559c57ef4b6525e9d7ded688ac"].pack("H*"),
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

    string = "2 OP_TOALTSTACK 0 OP_TOALTSTACK OP_TUCK OP_CHECKSIG OP_SWAP OP_HASH160 3cd1def404e12a85ead2b4d3f5f9f817fb0d46ef OP_EQUAL OP_BOOLAND OP_FROMALTSTACK OP_ADD"
    Bitcoin::Script.from_string(string).to_string.should == string
  end

  it '#get_pubkey' do
    Bitcoin::Script.new(@script[0]).get_pubkey.should ==
      "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
  end

  it '#get_pubkey_address' do
    Bitcoin::Script.new(@script[0]).get_pubkey_address.should ==
      "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"
  end

  it "#get_hash160" do
    Bitcoin::Script.new(@script[2]).get_hash160.should ==
      "17977bca1b6287a5e6559c57ef4b6525e9d7ded6"
  end

  it "#get_hash160_address" do
    Bitcoin::Script.new(@script[2]).get_hash160_address.should ==
      "139k1g5rtTsL4aGZbcASH3Fv3fUh9yBEdW"
  end

  it "#get_address" do
    Bitcoin::Script.new(@script[0]).get_address.should ==
      "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"
    Bitcoin::Script.new(@script[1]).get_address.should == nil
    Bitcoin::Script.new(@script[2]).get_address.should ==
      "139k1g5rtTsL4aGZbcASH3Fv3fUh9yBEdW"
  end

  it '#is_send_to_ip?' do
    Bitcoin::Script.new(@script[0]).is_send_to_ip?.should == true
    Bitcoin::Script.new(@script[1]).is_send_to_ip?.should == false
    Bitcoin::Script.new(@script[2]).is_send_to_ip?.should == false
  end

  it "#is_hash160?" do
    Bitcoin::Script.new(@script[0]).is_hash160?.should == false
    Bitcoin::Script.new(@script[1]).is_send_to_ip?.should == false
    Bitcoin::Script.new(@script[2]).is_hash160?.should == true
  end

  it '#run' do
    script = @script[1] + @script[0]
    Bitcoin::Script.new(script).run.should == true
    # TODO test more scripts
  end
end
