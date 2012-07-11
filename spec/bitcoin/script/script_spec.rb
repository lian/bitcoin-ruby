require_relative '../spec_helper.rb'
require 'bitcoin/script'

include Bitcoin

describe 'Bitcoin::Script' do
  SCRIPT = [
    "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac",
    "47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901",
    "76a91417977bca1b6287a5e6559c57ef4b6525e9d7ded688ac",
    "524104573b6e9f3a714440048a7b87d606bcbf9e45b8586e70a67a3665ea720c095658471a523e5d923f3f3e015626e7c900bd08560ddffeb17d33c5b52c96edb875954104039c2f4e413a26901e67ad4adbb6a4759af87bc16c7120459ecc9482fed3dd4a4502947f7b4c7782dcadc2bed513ed14d5e770452b97ae246ac2030f13b80a5141048b0f9d04e495c3c754f8c3c109196d713d0778882ef098f785570ee6043f8c192d8f84df43ebafbcc168f5d95a074dc4010b62c003e560abc163c312966b74b653ae", # multisig 2 of 3
    "5141040ee607b584b36e995f2e96dec35457dbb40845d0ce0782c84002134e816a6b8cbc65e9eed047ae05e10760e4113f690fd49ad73b86b04a1d7813d843f8690ace4104220a78f5f6741bb0739675c2cc200643516b02cfdfda5cba21edeaa62c0f954936b30dfd956e3e99af0a8e7665cff6ac5b429c54c418184c81fbcd4bde4088f552ae", # multisig 1 of 2
  ].map{|s|[s].pack("H*")}
  PUBKEYS = [
    "04fb0123fe2c399981bc77d522e2ae3268d2ab15e9a84ae49338a4b1db3886a1ea04cdab955d81e9fa1fcb0c062cb9a5af1ad5dd5064f4afcca322402b07030ec2",
    "0423b8161514560bc8638054b6637ab78f400b24e5694ec8061db635d1f28a17902b14dbf4f80780da659ab24f11ded3095c780452a4004c30ab58dffac33d839a",
    "04f43e76afac66bf3927638b6c4f7e324513ce56d2d658ac9d24c420d09993a4464eea6141a68a4748c092ad0e8f4ac29c4a2f661ef4d22b21f20110f42fcd6f6d",
  ]
  describe "serialization" do
    it '#to_string' do
      Script.new(SCRIPT[0]).to_string.should ==
        "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3 OP_CHECKSIG"

      Script.new(SCRIPT[1]).to_string.should ==
        "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"

      Script.new([123].pack("C")).to_string.should == "(opcode 123)"
      Script.new([176].pack("C")).to_string.should == "OP_EVAL"

      Script.from_string("1 OP_DROP 2").to_string.should == "1 OP_DROP 2"
    end

    it 'Script#binary_from_string' do
      str = Script.new(SCRIPT[0]).to_string
      Script.binary_from_string(str).unpack("H*")[0].should == SCRIPT[0].unpack("H*")[0]
      Script.new(Script.binary_from_string(str)).to_string.should == str

      str = Script.new(SCRIPT[1]).to_string
      Script.binary_from_string(str).unpack("H*")[0].should == SCRIPT[1].unpack("H*")[0]
      Script.new(Script.binary_from_string(str)).to_string.should == str
      # TODO make tests for OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 cases

      string = "2 OP_TOALTSTACK 0 OP_TOALTSTACK OP_TUCK OP_CHECKSIG OP_SWAP OP_HASH160 3cd1def404e12a85ead2b4d3f5f9f817fb0d46ef OP_EQUAL OP_BOOLAND OP_FROMALTSTACK OP_ADD"
      Script.from_string(string).to_string.should == string

      Script.from_string("0 OP_DROP 2 3 4").to_string.should == "0 OP_DROP 2 3 4"

      Script.from_string("OP_EVAL").to_string.should == "OP_EVAL"
      Script.from_string("OP_NOP1").to_string.should == "OP_EVAL" # test opcodes_alias table
      Script.from_string("OP_NOP").to_string.should == "OP_NOP"
      Script.from_string("1").to_string.should == "1"

      Script.from_string("0 ffff OP_CODESEPARATOR 1 ffff 1 OP_CHECKMULTISIG").to_string.should == "0 ffff OP_CODESEPARATOR 1 ffff 1 OP_CHECKMULTISIG"

      [1,2,4].all?{|n| script = "OP_PUSHDATA#{n} 01 ff"
        Bitcoin::Script.binary_from_string(script) == Bitcoin::Script.binary_from_string( Bitcoin::Script.from_string(script).to_string )
      }.should == true

      proc{ Script.from_string("OP_NOP OP_UNKOWN") }.should.raise(Script::ScriptOpcodeError).message.should == "OP_UNKOWN not defined!"
    end
  end

  describe "get keys/addresses" do
    it '#get_pubkey' do
      Script.new(SCRIPT[0]).get_pubkey.should ==
        "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
    end

    it '#get_pubkey_address' do
      Script.new(SCRIPT[0]).get_pubkey_address.should ==
        "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"
    end

    it "#get_hash160" do
      Script.new(SCRIPT[2]).get_hash160.should ==
        "17977bca1b6287a5e6559c57ef4b6525e9d7ded6"
      Script.from_string("OP_DUP OP_HASH160 0 OP_EQUALVERIFY OP_CHECKSIG")
        .get_hash160.should == nil
    end

    it "#get_hash160_address" do
      Script.new(SCRIPT[2]).get_hash160_address.should ==
        "139k1g5rtTsL4aGZbcASH3Fv3fUh9yBEdW"
    end

    it "#get_multisig_pubkeys" do
      Script.new(SCRIPT[3]).get_multisig_pubkeys.should == [
        "04573b6e9f3a714440048a7b87d606bcbf9e45b8586e70a67a3665ea720c095658471a523e5d923f3f3e015626e7c900bd08560ddffeb17d33c5b52c96edb87595",
        "04039c2f4e413a26901e67ad4adbb6a4759af87bc16c7120459ecc9482fed3dd4a4502947f7b4c7782dcadc2bed513ed14d5e770452b97ae246ac2030f13b80a51",
        "048b0f9d04e495c3c754f8c3c109196d713d0778882ef098f785570ee6043f8c192d8f84df43ebafbcc168f5d95a074dc4010b62c003e560abc163c312966b74b6"].map{|pk| [pk].pack("H*")}
      Script.from_string("3 #{PUBKEYS[0..2].join(' ')} 3 OP_CHECKMULTISIG")
        .get_multisig_pubkeys.should == [
        "04fb0123fe2c399981bc77d522e2ae3268d2ab15e9a84ae49338a4b1db3886a1ea04cdab955d81e9fa1fcb0c062cb9a5af1ad5dd5064f4afcca322402b07030ec2",
        "0423b8161514560bc8638054b6637ab78f400b24e5694ec8061db635d1f28a17902b14dbf4f80780da659ab24f11ded3095c780452a4004c30ab58dffac33d839a",
        "04f43e76afac66bf3927638b6c4f7e324513ce56d2d658ac9d24c420d09993a4464eea6141a68a4748c092ad0e8f4ac29c4a2f661ef4d22b21f20110f42fcd6f6d"].map{|k|[k].pack("H*")}
    end

    it "#get_multisig_addresses" do
      Script.new(SCRIPT[3]).get_multisig_addresses.should == [
        "1JiaVc3N3U3CwwcLtzNX1Q4eYfeYxVjtuj", "19Fm2gY7qDTXriNTEhFY2wjxbHna3Gvenk",
        "1B6k6g1d2L975i7beAbiBRxfBWhxomPxvy"]
      Script.new(SCRIPT[4]).get_multisig_addresses.should == [
        "1F2Nnyn7niMcheiYhkHrkc18aDxEkFowy5", "1EE7JGimkV7QqyHwXDJvk3b1yEN4ZUWeqx"]
    end

    it "#get_address" do
      Script.new(SCRIPT[0]).get_address.should ==
        "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"
      Script.new(SCRIPT[1]).get_address.should == nil
      Script.new(SCRIPT[2]).get_address.should ==
        "139k1g5rtTsL4aGZbcASH3Fv3fUh9yBEdW"
      Script.new(SCRIPT[3]).get_address.should == 
        "1JiaVc3N3U3CwwcLtzNX1Q4eYfeYxVjtuj"
      Script.new(SCRIPT[4]).get_address.should == 
        "1F2Nnyn7niMcheiYhkHrkc18aDxEkFowy5"
    end

    it "#get_addresses" do
      Script.new(SCRIPT[0]).get_addresses.
        should == ["12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"]
      Script.new(SCRIPT[3]).get_addresses
        .should == ["1JiaVc3N3U3CwwcLtzNX1Q4eYfeYxVjtuj",
        "19Fm2gY7qDTXriNTEhFY2wjxbHna3Gvenk", "1B6k6g1d2L975i7beAbiBRxfBWhxomPxvy"]
    end
  end

  describe "determine type" do

    it '#is_standard?' do
      Script.new(SCRIPT[0]).is_standard?.should == true
      Script.new(SCRIPT[1]).is_standard?.should == false
      Script.new(SCRIPT[2]).is_standard?.should == true
      Script.new(SCRIPT[3]).is_standard?.should == true
      Script.new(SCRIPT[4]).is_standard?.should == true
    end

    it '#is_pubkey?' do
      Script.new(SCRIPT[0]).is_pubkey?.should == true
      Script.new(SCRIPT[1]).is_pubkey?.should == false
      Script.new(SCRIPT[2]).is_pubkey?.should == false
      Script.new(SCRIPT[3]).is_pubkey?.should == false
      Script.new(SCRIPT[4]).is_send_to_ip?.should == false
    end

    it "#is_hash160?" do
      Script.new(SCRIPT[0]).is_hash160?.should == false
      Script.new(SCRIPT[1]).is_pubkey?.should == false
      Script.new(SCRIPT[2]).is_hash160?.should == true
      Script.from_string("OP_DUP OP_HASH160 0 OP_EQUALVERIFY OP_CHECKSIG")
        .is_hash160?.should == false
    end

    it "#is_multisig?" do
      Script.new(SCRIPT[3]).is_multisig?.should == true
      Script.new(SCRIPT[4]).is_multisig?.should == true
      Script.new(SCRIPT[0]).is_multisig?.should == false
      Script.new("OP_DUP OP_DROP 2 #{PUBKEYS[0..2].join(' ')} 3 OP_CHECKMULTISIG")
        .is_multisig?.should == false
      Script.new("OP_DROP OP_CHECKMULTISIG").is_multisig?.should == false
    end

    it "#type" do
      Script.new(SCRIPT[0]).type.should == :pubkey
      Script.new(SCRIPT[1]).type.should == :unknown
      Script.new(SCRIPT[2]).type.should == :hash160
      Script.new(SCRIPT[3]).type.should == :multisig
      Script.new(SCRIPT[4]).type.should == :multisig
    end

  end

  describe "generate scripts" do

    it "should generate pubkey script" do
      Script.to_pubkey_script(PUBKEYS[0]).should ==
        Script.from_string("#{PUBKEYS[0]} OP_CHECKSIG").raw
      Script.to_pubkey_script(PUBKEYS[1]).should ==
        Script.from_string("#{PUBKEYS[1]} OP_CHECKSIG").raw
    end

    it "should generate hash160 script" do
      Script.to_address_script('16Tc7znw2mfpWcqS84vBFfJ7PyoeHaXSz9')
        .should == ["76a9143be0c2daaabbf3d53e47352c19d1e8f047e2f94188ac"].pack("H*")
      hash160 = Bitcoin.hash160_from_address('16Tc7znw2mfpWcqS84vBFfJ7PyoeHaXSz9')
      Script.to_hash160_script(hash160)
        .should == Script.from_string("OP_DUP OP_HASH160 #{hash160} OP_EQUALVERIFY OP_CHECKSIG").raw
      Script.to_address_script('mr1jU3Adw2pkvxTLvQA4MKpXB9Dynj9cXF')
        .should == nil
    end

    it "should generate multisig script" do
      Script.to_multisig_script(2, *PUBKEYS[0..2]).should ==
        Script.from_string("2 #{PUBKEYS[0..2].join(' ')} 3 OP_CHECKMULTISIG").raw
      Script.to_multisig_script(1, *PUBKEYS[0..1]).should ==
        Script.from_string("1 #{PUBKEYS[0..1].join(' ')} 2 OP_CHECKMULTISIG").raw
    end

    it "should generate p2sh script" do
      address = "3CkxTG25waxsmd13FFgRChPuGYba3ar36B"
      hash160 = Bitcoin.hash160_from_address address
      Script.to_p2sh_script(hash160).should == 
        Script.from_string("OP_HASH160 #{hash160} OP_EQUAL").raw
    end

    it "should determine type for address script" do
      address = '16Tc7znw2mfpWcqS84vBFfJ7PyoeHaXSz9'
      hash160 = Bitcoin.hash160_from_address address
      Script.to_address_script(address).should ==
        Script.from_string("OP_DUP OP_HASH160 #{hash160} OP_EQUALVERIFY OP_CHECKSIG").raw

      address = "3CkxTG25waxsmd13FFgRChPuGYba3ar36B"
      hash160 = Bitcoin.hash160_from_address address
      Script.to_p2sh_script(hash160).should == 
        Script.from_string("OP_HASH160 #{hash160} OP_EQUAL").raw
    end

  end

  describe "generate script sigs" do

    it "should generate pubkey script sig" do
      sig = ["3045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec"].pack("H*")
      pub = ["04bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c"].pack("H*")
      Script.to_pubkey_script_sig(sig, pub)
        .should == ["483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec014104bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c"].pack("H*")
    end

  end

  it '#run' do
    script = SCRIPT[1] + SCRIPT[0]
    Script.new(script).run.should == true

    Script.from_string("1 OP_DUP OP_DROP 1 OP_EQUAL")
      .run.should == true
    Script.from_string("1 OP_DUP OP_DROP 1 OP_EQUAL")
      .run.should == true
    Script.from_string("foo OP_DUP OP_DROP foo OP_EQUAL")
      .run.should == true
    Script.from_string("bar foo OP_DUP OP_DROP bar OP_EQUAL")
      .run.should == false

    Script.from_string("1 OP_DROP 2").run.should == true
  end

end
