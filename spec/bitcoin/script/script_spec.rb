# encoding: ascii-8bit

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
    "a9149471864495192e39f5f74574b6c8c513588a820487", # p2sh
    "6a04deadbeef", # OP_RETURN deadbeef
    "00141e205151c90c16475363d11b7b8c235cf6c7d695", # p2wpkh
    "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0" # p2wsh
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

      #Script.new([123].pack("C")).to_string.should == "(opcode 123)"
      Script.new([176].pack("C")).to_string.should == "OP_NOP1"
      Script.from_string("1 OP_DROP 2").to_string.should == "1 OP_DROP 2"

      Script.from_string("4b").to_string.should == "4b"
      Script.from_string("4b").to_payload.should == "\x01\x4b"
      Script.from_string("ff").to_string.should == "ff"
      Script.from_string("ff").to_payload.should == "\x01\xff"
      Script.from_string("ffff").to_string.should == "ffff"

      Script.from_string( "ff"*(Script::OP_PUSHDATA1-1) ).to_payload[0]   .should == [Script::OP_PUSHDATA1-1].pack("C*")
      Script.from_string( "ff"*Script::OP_PUSHDATA1     ).to_payload[0..1].should == [Script::OP_PUSHDATA1, Script::OP_PUSHDATA1].pack("C*")
      Script.from_string( "ff"*(Script::OP_PUSHDATA1+1) ).to_payload[0..1].should == [Script::OP_PUSHDATA1, Script::OP_PUSHDATA1+1].pack("C*")
      Script.from_string( "ff"*0xff                     ).to_payload[0..1].should == [Script::OP_PUSHDATA1, 0xff].pack("C*")
      Script.from_string( "ff"*(0xff+1)                 ).to_payload[0..2].should == [Script::OP_PUSHDATA2, 0x00, 0x01].pack("C*")
      Script.from_string( "ff"*0xffff                   ).to_payload[0..2].should == [Script::OP_PUSHDATA2, 0xff, 0xff].pack("C*")
      Script.from_string( "ff"*(0xffff+1)               ).to_payload[0..4].should == [Script::OP_PUSHDATA4, 0x00, 0x00, 0x01, 0x00].pack("C*")

      Script.from_string("16").to_string.should == "16"
      Script::OP_2_16.include?(Script.from_string("16").chunks.first).should == true
      Script.from_string("16").to_payload.should == "\x60"
      Script.new("\x60").to_string.should == "16"

      Script.from_string("0:1:16").to_string.should == "0:1:16"
      Script::OP_2_16.include?(Script.from_string("0:1:16").chunks.first).should == false
      Script.from_string("0:1:16").to_payload.should == "\x01\x16"
      Script.new("\x01\x16").to_string.should == "0:1:16"

      Script.new("\x4d\x01\x00\x02").to_string.should == "77:1:02"
      Script.from_string("77:1:02").to_payload.should == "\x4d\x01\x00\x02"
      Script.from_string("77:1:01").to_string.should == "77:1:01"
      Script.from_string("77:2:0101").to_string.should == "77:2:0101"
      Script.from_string("78:1:01").to_string.should == "78:1:01"
      Script.from_string("78:2:0101").to_string.should == "78:2:0101"
      Script.new("\x4e\x01\x00\x00\x00\x02").to_string.should == "78:1:02"
      Script.from_string("78:1:02").to_payload.should == "\x4e\x01\x00\x00\x00\x02"

      Script.new("\x4d\x01\x00").to_string.should == "77:1:"
      Script.from_string("77:1:").to_payload.should == "\x4d\x01\x00"

      [ # mainnet tx: ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767 outputs
        ["\x01",                        "238:1:01",            true],
        ["\x02\x01",                    "238:2:0201",          true],
        ["L",                           "238:1:4c",            true],
        ["L\x02\x01",                   "76:2:01",              nil],
        ["M",                           "238:1:4d",            true],
        ["M\xff\xff\x01",               "238:4:4dffff01",      true],
        ["N",                           "238:1:4e",            true],
        ["N\xff\xff\xff\xff\x01",       "238:6:4effffffff01",  true],
      ].each{|payload,string,parse_invalid|
        Script.new(payload).to_string.should == string
        Script.new(payload).instance_eval{ @parse_invalid }.should == parse_invalid
        Script.from_string(string).to_payload == payload
      }

      Bitcoin::Script.from_string("(opcode-230) 4 1 2").to_string.should == "(opcode-230) 4 1 2"
      Bitcoin::Script.from_string("(opcode 230) 4 1 2").to_string.should == "(opcode-230) 4 1 2"
      Bitcoin::Script.from_string("(opcode-65449) 4 1 2").to_string.should == "OP_INVALIDOPCODE OP_HASH160 4 1 2"

      # found in testnet3 block 0000000000ac85bb2530a05a4214a387e6be02b22d3348abc5e7a5d9c4ce8dab transactions
      Script.new("\xff\xff\xff\xff").to_string.should == "OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE"
      Script.from_string(Script.new("\xff\xff\xff\xff").to_string).raw.should == "\xFF\xFF\xFF\xFF"
      Script.new("\xff\xff\xff").to_string.should == "OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE"
      Script.from_string(Script.new("\xff\xff\xff").to_string).raw.should == "\xFF\xFF\xFF"
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

      Script.from_string("OP_EVAL").to_string.should == "OP_NOP1"
      Script.from_string("OP_NOP1").to_string.should == "OP_NOP1" # test opcodes_alias table
      Script.from_string("OP_NOP").to_string.should == "OP_NOP"
      Script.from_string("1").to_string.should == "1"

      Script.from_string("0 ffff OP_CODESEPARATOR 1 ffff 1 OP_CHECKMULTISIG").to_string.should == "0 ffff OP_CODESEPARATOR 1 ffff 1 OP_CHECKMULTISIG"

      [1,2,4].all?{|n| script = "OP_PUSHDATA#{n} 01 ff"
        Bitcoin::Script.binary_from_string(script) == Bitcoin::Script.binary_from_string( Bitcoin::Script.from_string(script).to_string )
      }.should == true

      #Script.from_string("-100").to_string.should == "OP_NOP"
      #Script.from_string("100").to_string.should == "100"

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
      Script.new(SCRIPT[7]).get_hash160.should == "1e205151c90c16475363d11b7b8c235cf6c7d695"
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

      # from tx 274f8be3b7b9b1a220285f5f71f61e2691dd04df9d69bb02a8b3b85f91fb1857, second pubkey has invalid encoding.
      output = "1 0351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da78 00f2b7816db49d55d24df7bdffdbc1e203b424e8cd39f5651ab938e5e4a193569e 2 OP_CHECKMULTISIG"
      Bitcoin::Script.from_string(output).get_multisig_addresses.should == ["1NdB761LmTmrJixxp93nz7pEiCx5cKPW44", nil]
    end

    it "#get_p2sh_address" do
      Script.new(SCRIPT[5]).get_p2sh_address.should ==
        "3FDuvkgzsW7LpzL9RBjtjvL7bFXCEeZ7xi"
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
      Script.new(SCRIPT[5]).get_address.should ==
        "3FDuvkgzsW7LpzL9RBjtjvL7bFXCEeZ7xi"
    end

    it "#get_addresses" do
      Script.new(SCRIPT[0]).get_addresses.
        should == ["12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"]
      Script.new(SCRIPT[3]).get_addresses
        .should == ["1JiaVc3N3U3CwwcLtzNX1Q4eYfeYxVjtuj",
        "19Fm2gY7qDTXriNTEhFY2wjxbHna3Gvenk", "1B6k6g1d2L975i7beAbiBRxfBWhxomPxvy"]
    end

    it "should get op_return data" do
      Script.new(SCRIPT[6]).get_op_return_data.should == "deadbeef"
      Script.new(SCRIPT[1]).get_op_return_data.should == nil
      Script.from_string("OP_RETURN").get_op_return_data.should == nil
      Script.from_string("OP_RETURN dead beef").get_op_return_data.should == nil
      Script.from_string("OP_RETURN deadbeef").get_op_return_data.should == "deadbeef"
      Script.from_string("OP_RETURN OP_CHECKSIG").get_op_return_data.should == "ac00"
    end
  end

  describe "determine type" do

    it '#is_standard?' do
      Script.new(SCRIPT[0]).is_standard?.should == true
      Script.new(SCRIPT[1]).is_standard?.should == false
      Script.new(SCRIPT[2]).is_standard?.should == true
      Script.new(SCRIPT[3]).is_standard?.should == true
      Script.new(SCRIPT[4]).is_standard?.should == true
      Script.new(SCRIPT[5]).is_standard?.should == true
      Script.new(SCRIPT[6]).is_standard?.should == true
      Script.new(SCRIPT[7]).is_standard?.should == true
      Script.new(SCRIPT[8]).is_standard?.should == true
    end

    it '#is_pubkey?' do
      Script.new(SCRIPT[0]).is_pubkey?.should == true
      Script.new(SCRIPT[1]).is_pubkey?.should == false
      Script.new(SCRIPT[2]).is_pubkey?.should == false
      Script.new(SCRIPT[3]).is_pubkey?.should == false
      Script.new(SCRIPT[4]).is_send_to_ip?.should == false
      Script.new(SCRIPT[5]).is_pubkey?.should == false
      Script.new(SCRIPT[6]).is_pubkey?.should == false
      Script.new(SCRIPT[7]).is_pubkey?.should == false
      Script.new(SCRIPT[8]).is_pubkey?.should == false
      Script.from_string("0 OP_CHECKSIG").is_pubkey?.should == false # testnet aba0441c4c9933dcd7db789c39053739ec435ab742ed2c23c05f22f1488c0bfd
    end

    it "#is_hash160?" do
      Script.new(SCRIPT[0]).is_hash160?.should == false
      Script.new(SCRIPT[1]).is_pubkey?.should == false
      Script.new(SCRIPT[2]).is_hash160?.should == true
      Script.from_string("OP_DUP OP_HASH160 0 OP_EQUALVERIFY OP_CHECKSIG")
        .is_hash160?.should == false
      Script.new(SCRIPT[5]).is_hash160?.should == false
      Script.new(SCRIPT[6]).is_hash160?.should == false
      Script.new(SCRIPT[7]).is_hash160?.should == false
      Script.new(SCRIPT[8]).is_hash160?.should == false
    end

    it "#is_multisig?" do
      Script.new(SCRIPT[3]).is_multisig?.should == true
      Script.new(SCRIPT[4]).is_multisig?.should == true
      Script.new(SCRIPT[0]).is_multisig?.should == false
      Script.new(SCRIPT[6]).is_multisig?.should == false
      Script.new(SCRIPT[7]).is_multisig?.should == false
      Script.new(SCRIPT[8]).is_multisig?.should == false
      Script.new("OP_DUP OP_DROP 2 #{PUBKEYS[0..2].join(' ')} 3 OP_CHECKMULTISIG")
        .is_multisig?.should == false
      Script.new("OP_DROP OP_CHECKMULTISIG").is_multisig?.should == false
      Script.from_string("d366fb5cbf048801b1bf0742bb0d873f65afb406f41756bd4a31865870f6a928 OP_DROP 2 02aae4b5cd593da83679a9c5cadad4c180c008a40dd3ed240cceb2933b9912da36 03a5aebd8b1b6eec06abc55fb13c72a9ed2143f9eed7d665970e38853d564bf1ab OP_CHECKMULTISIG").is_multisig?.should == false
    end

    it '#is_p2sh?' do
      Script.new(SCRIPT[0]).is_p2sh?.should == false
      Script.new(SCRIPT[1]).is_p2sh?.should == false
      Script.new(SCRIPT[2]).is_p2sh?.should == false
      Script.new(SCRIPT[3]).is_p2sh?.should == false
      Script.new(SCRIPT[4]).is_p2sh?.should == false
      Script.new(SCRIPT[5]).is_p2sh?.should == true
      Script.new(SCRIPT[6]).is_p2sh?.should == false
      Script.new(SCRIPT[7]).is_p2sh?.should == false
      Script.new(SCRIPT[8]).is_p2sh?.should == false
      Script.from_string("OP_DUP OP_HASH160 b689ebc262f50297139e7d16c4f8909e14ed4322 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_HASH160 1b6246121883816fc0637e4aa280aca1df219b1a OP_EQUAL")
        .is_p2sh?.should == false
    end

    it '#is_op_return?' do
      Script.new(SCRIPT[0]).is_op_return?.should == false
      Script.new(SCRIPT[1]).is_op_return?.should == false
      Script.new(SCRIPT[2]).is_op_return?.should == false
      Script.new(SCRIPT[3]).is_op_return?.should == false
      Script.new(SCRIPT[4]).is_op_return?.should == false
      Script.new(SCRIPT[5]).is_op_return?.should == false
      Script.new(SCRIPT[6]).is_op_return?.should == true
      Script.new(SCRIPT[7]).is_op_return?.should == false
      Script.new(SCRIPT[8]).is_op_return?.should == false
      Script.from_string("OP_RETURN dead beef").is_op_return?.should == false
      Script.from_string("OP_RETURN deadbeef").is_op_return?.should == true
      Script.from_string("OP_RETURN OP_CHECKSIG").is_op_return?.should == true
    end

    it '#is_witness_v0_keyhash?' do
      Script.new(SCRIPT[0]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[1]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[2]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[3]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[4]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[5]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[6]).is_witness_v0_keyhash?.should == false
      Script.new(SCRIPT[7]).is_witness_v0_keyhash?.should == true
      Script.new(SCRIPT[8]).is_witness_v0_keyhash?.should == false
    end

    it '#is_witness_v0_scripthash?' do
      Script.new(SCRIPT[0]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[1]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[2]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[3]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[4]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[5]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[6]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[7]).is_witness_v0_scripthash?.should == false
      Script.new(SCRIPT[8]).is_witness_v0_scripthash?.should == true
    end

    it "#type" do
      Script.new(SCRIPT[0]).type.should == :pubkey
      Script.new(SCRIPT[1]).type.should == :unknown
      Script.new(SCRIPT[2]).type.should == :hash160
      Script.new(SCRIPT[3]).type.should == :multisig
      Script.new(SCRIPT[4]).type.should == :multisig
      Script.new(SCRIPT[5]).type.should == :p2sh
      Script.new(SCRIPT[6]).type.should == :op_return
      Script.new(SCRIPT[7]).type.should == :witness_v0_keyhash
      Script.new(SCRIPT[8]).type.should == :witness_v0_scripthash
      Script.from_string("OP_RETURN OP_CHECKSIG").type.should == :op_return
      Script.from_string("OP_RETURN dead beef").type.should == :unknown
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

      m=n=16; Bitcoin::Script.new(Bitcoin::Script.to_multisig_script(m, *(["a"]*n))).to_string
        .should == "16 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 16 OP_CHECKMULTISIG"
      m=n=17; Bitcoin::Script.new(Bitcoin::Script.to_multisig_script(m, *(["a"]*n))).to_string
        .should == "0:1:11 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 0:1:11 OP_CHECKMULTISIG"
      m=n=20; Bitcoin::Script.new(Bitcoin::Script.to_multisig_script(m, *(["a"]*n))).to_string
        .should == "0:1:14 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 a0 0:1:14 OP_CHECKMULTISIG"
    end

    it "should generate p2sh script" do
      address = "3CkxTG25waxsmd13FFgRChPuGYba3ar36B"
      hash160 = Bitcoin.hash160_from_address address
      Script.to_p2sh_script(hash160).should ==
        Script.from_string("OP_HASH160 #{hash160} OP_EQUAL").raw
    end

    it "to_witness_hash160_script" do
      hash160 = Bitcoin.hash160('025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357')
      Script.to_witness_hash160_script(hash160).should == Script.new("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1".htb).raw
    end

    it "should generate p2wsh script" do
      witness_script = '21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac'
      sha256 = Bitcoin.sha256(witness_script)
      Script.to_witness_p2sh_script(sha256).should == Script.new("00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0".htb).raw
    end

    it "should generate op_return script" do
      Script.to_op_return_script("deadbeef").should == SCRIPT[6]
      Script.to_op_return_script.should == Script.from_string("OP_RETURN").raw
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
    before do
      @sig = '3045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec'.htb
    end

    it "should generate pubkey script sig" do
      pub = '04bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c'.htb
      expected_script = '483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec014104bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c'.htb

      Script.to_pubkey_script_sig(@sig, pub).should == expected_script
    end

    it "should accept a compressed public key as input" do
      pub = '02bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41'.htb
      expected_script = '483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec012102bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41'.htb

      Script.to_pubkey_script_sig(@sig, pub).should == expected_script
    end

    it "should reject an improperly encoding public key" do
      # Not binary encoded, like it's supposed to be.
      pub = '02bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41'

      lambda {
        Script.to_pubkey_script_sig(@sig, pub)
      }.should.raise
    end

    it "should support different hash types" do
      hash_type = Script::SIGHASH_TYPE[:single]
      pub = '04bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c'.htb
      expected_script = '483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec034104bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c'.htb

      Script.to_pubkey_script_sig(@sig, pub, hash_type).should == expected_script
    end

    it "should generate multisig script sig" do
      hash_type = Script::SIGHASH_TYPE[:none]
      expected_script = '00483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec02483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec02'.htb

      Script.to_multisig_script_sig(@sig, @sig, hash_type).should == expected_script
    end
  end


  describe "signatures_count" do

    it "should be zero in data-only scripts" do
      [false, true].each do |accurate|
        Script.from_string("").sigops_count_accurate(accurate).should == 0
        Script.from_string("DEADBEEF").sigops_count_accurate(accurate).should == 0
        Script.from_string("DEAD BEEF").sigops_count_accurate(accurate).should == 0
        Script.from_string("DE AD BE EF").sigops_count_accurate(accurate).should == 0
        Script.from_string("OP_NOP").sigops_count_accurate(accurate).should == 0
        Script.from_string("0").sigops_count_accurate(accurate).should == 0
        Script.from_string("0 1").sigops_count_accurate(accurate).should == 0
        Script.from_string("0 1 2 3").sigops_count_accurate(accurate).should == 0
      end
    end

    it "should count sigops" do
      [false, true].each do |accurate|
        Script.from_string("OP_CHECKSIG").sigops_count_accurate(accurate).should == 1
        Script.from_string("OP_CHECKSIGVERIFY").sigops_count_accurate(accurate).should == 1
        Script.from_string("OP_CHECKSIG OP_CHECKSIGVERIFY").sigops_count_accurate(accurate).should == 2
        Script.from_string("OP_CHECKSIG OP_CHECKSIG OP_CHECKSIG OP_CHECKSIG").sigops_count_accurate(accurate).should == 4
        Script.from_string("1 OP_CHECKSIG 2 OP_CHECKSIG DEADBEEF OP_CHECKSIG 3 OP_CHECKSIG 4").sigops_count_accurate(accurate).should == 4
      end
    end

    it "should count multisig as 20 sigops in legact inaccurate mode" do
      Script.from_string("OP_CHECKMULTISIG").sigops_count_accurate(false).should == 20
      Script.from_string("OP_CHECKMULTISIGVERIFY").sigops_count_accurate(false).should == 20
      Script.from_string("OP_CHECKMULTISIG OP_CHECKMULTISIGVERIFY").sigops_count_accurate(false).should == 40
      Script.from_string("1 OP_CHECKMULTISIG").sigops_count_accurate(false).should == 20
      Script.from_string("5 OP_CHECKMULTISIG").sigops_count_accurate(false).should == 20
      Script.from_string("40 OP_CHECKMULTISIG").sigops_count_accurate(false).should == 20
    end

    it "should count multisig accurately using number of pubkeys" do
      Script.from_string("1 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 1
      Script.from_string("1 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 1
      Script.from_string("2 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 2
      Script.from_string("2 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 2
      Script.from_string("15 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 15
      Script.from_string("15 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 15
      Script.from_string("16 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 16
      Script.from_string("16 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 16
      Script.from_string("4 OP_CHECKMULTISIG 7 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 11
    end

    it "should count multisig as 20 sigops in accurate mode when the pubkey count is missing" do
      Script.from_string("OP_CHECKMULTISIG").sigops_count_accurate(true).should == 20
      Script.from_string("OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 20
    end

    it "should count multisig as 20 sigops when pubkey count is not OP_{1,...,16}, but bignum as pushdata" do
      Script.from_string("#{Script::OP_PUSHDATA1}:1:01 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 20
      Script.from_string("#{Script::OP_PUSHDATA1}:1:02 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 20
    end

    it "should count multisig as 20 sigops in accurate mode when the pubkey count is out of bounds" do
      Script.from_string("0 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 20
      Script.from_string("0 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 20
      Script.from_string("0 OP_CHECKMULTISIG 0 OP_CHECKMULTISIGVERIFY").sigops_count_accurate(true).should == 40
      Script.from_string("DEADBEEF OP_CHECKMULTISIG").sigops_count_accurate(true).should == 20
      Script.from_string("#{Script::OP_PUSHDATA1}:1:11 OP_CHECKMULTISIG").sigops_count_accurate(true).should == 20
    end

    it "should extract signature count from P2SH scriptSig" do

      # Given a P2SH input script (the one with the signatures and a serialized script inside)
      # This should count as 12 sigops (1 + 4 + 7)
      script = Script.from_string("OP_CHECKSIG 4 OP_CHECKMULTISIG 7 OP_CHECKMULTISIGVERIFY")

      # Serialize the script to be used as a plain pushdata (which will be decoded as a script).
      serialized_script = Script.new("").append_pushdata(script.to_binary)

      # If empty should return 0.
      Script.from_string("").sigops_count_for_p2sh.should == 0

      # If ends with OP_N
      Script.from_string("0").sigops_count_for_p2sh.should == 0
      Script.from_string("1").sigops_count_for_p2sh.should == 0
      Script.from_string("5").sigops_count_for_p2sh.should == 0
      Script.from_string("16").sigops_count_for_p2sh.should == 0

      # If ends with opcode
      Script.from_string("OP_NOP").sigops_count_for_p2sh.should == 0
      Script.from_string("OP_HASH160").sigops_count_for_p2sh.should == 0
      Script.from_string("OP_CHECKSIG").sigops_count_for_p2sh.should == 0
      Script.from_string("DEADBEEF OP_NOP").sigops_count_for_p2sh.should == 0
      Script.from_string("DEADBEEF OP_HASH160").sigops_count_for_p2sh.should == 0
      Script.from_string("DEADBEEF OP_CHECKSIG").sigops_count_for_p2sh.should == 0

      # If only has the script, should parse it well
      serialized_script.sigops_count_for_p2sh.should == 12

      # If ends with the script, should also parse well.
      Script.new(Script.from_string("DEADBEEF CAFEBABE").to_binary + serialized_script.to_binary).sigops_count_for_p2sh.should == 12
      Script.new(Script.from_string("DEADBEEF 1").to_binary + serialized_script.to_binary).sigops_count_for_p2sh.should == 12

      # If has the script, but ends with non-script, should return 0
      # DEADBEEF is a script with OP_CHECKSIGVERIFY in it, so we wrap it in a serialized script with plain pushdata to have 0 count.
      Script.new(serialized_script.to_binary + Script.new("").append_pushdata(Script.from_string("DEADBEEF").to_binary).to_binary).sigops_count_for_p2sh.should == 0
      Script.new(serialized_script.to_binary + Script.from_string("1").to_binary).sigops_count_for_p2sh.should == 0
    end

    it "should count sigops up until an invalid OP_PUSHDATA" do
      script_binary = Bitcoin::Protocol.read_binary_file(fixtures_path("txscript-invalid-too-many-sigops-followed-by-invalid-pushdata.bin"))
      Script.new(script_binary).sigops_count_accurate(false).should == 39998
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

    # testnet3 tx: 5dea81f9d9d2ea6d06ce23ff225d1e240392519017643f75c96fa2e4316d948a
    script = Script.new( ["0063bac0d0e0f0f1f2f3f3f4ff675168"].pack("H*") )
    script.to_string.should == "0 OP_IF (opcode-186) (opcode-192) (opcode-208) (opcode-224) (opcode-240) (opcode-241) (opcode-242) (opcode-243) (opcode-243) (opcode-244) OP_INVALIDOPCODE OP_ELSE 1 OP_ENDIF"
    script.run.should == true

    # mainnet tx: 61a078472543e9de9247446076320499c108b52307d8d0fafbe53b5c4e32acc4 redeeming output from 5342c96b946ea2c5e497de5dbf7762021f94aba2c8222c17ed28492fdbb4a6d9
    script = Bitcoin::Script.from_string("16cfb9bc7654ef1d7723e5c2722fc0c3d505045e OP_SIZE OP_DUP 1 OP_GREATERTHAN OP_VERIFY OP_NEGATE OP_HASH256 OP_HASH160 OP_SHA256 OP_SHA1 OP_RIPEMD160 OP_EQUAL")
    script.run.should == true

    # mainnet tx: 340aa9f72206d600b7e89c9137e4d2d77a920723f83e34707ff452121fd48492 redeeming output from f2d72a7bf22e29e3f2dc721afbf0a922860f81db9fc7eb397937f9d7e87cc438
    script = Bitcoin::Script.from_string("027ce87f6f41dd4d7d874b40889f7df6b288f77f OP_DEPTH OP_HASH256 OP_HASH160 OP_SHA256 OP_SHA1 OP_RIPEMD160 OP_EQUAL")
    script.run.should == true
  end

  it "should run op_checkmultisig p2sh script with empty signature" do
    # mainnet tx: b78706427923f73b334fd68040f35900503da33c671723c41ca845f6fba6c29c
    tx1 = Bitcoin::P::Tx.new("01000000023904cd3644c6d440a6d752c95f07737c46f5e70fb6fbb28f00aa17e281868b7b010000006b483045022100ac455750dc430957942e9766f88aecfe6eb17d4244eb2cb50ca4a25336fd4dd702202640cc943f4fe8f2166b03005bed3bd024f4762767322b60bf471ecf8e3f3ede012102348d4cad0084f88c4c02bdc1bf90cc6c0893a0b97af76ef644daf72e6786b4afffffffffb84057ae61ad22ac17c02635ee1b37d170ef785847ec28efe848a5607331568e020000006b483045022100d7fee595d7a1f9969767098f8582e7a563f08437f461f0a25395f35c1833839302205f565ab12d343478471a78669c4c3476714032f7758a781d7deab19f160784e0012102ea69c47753d8e0228c0c426294a6b4dc926aebbeb8561248d40be37d257d94e0ffffffff01a08601000000000017a91438430c4d1c214bf11d2c0c3dea8e5e9a5d11aab08700000000".htb)
    # mainnet tx: 136becd0892fa38c5aca8104db8b90b3a0e6b40912b7d1462aed583c067054cd
    tx2 = Bitcoin::P::Tx.new("01000000019cc2a6fbf645a81cc42317673ca33d500059f34080d64f333bf72379420687b70000000008000051005102ae91ffffffff0150c300000000000002ae9100000000".htb)
    tx2.verify_input_signature(0, tx1).should == true
  end

  it "should debug script branches (OP_IF/NOTIF/ELSE/ENDIF) correctly" do

    script = Bitcoin::Script.from_string("1 OP_NOTIF OP_RETURN OP_ENDIF")
    script.run {}
    script.debug.should == [
      [], "OP_1",
      [1], "OP_NOTIF",
      [], "OP_ENDIF",
      [], "RESULT"
    ]

    script = Bitcoin::Script.from_string("1 OP_IF OP_RETURN OP_ENDIF")
    script.run {}
    script.debug.should == [
      [], "OP_1",
      [1], "OP_IF",
      [], "OP_RETURN",
      [], "INVALID TRANSACTION", "RESULT"
    ]

    script = Bitcoin::Script.from_string("1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_2 OP_EQUAL")
    script.run {}
    script.debug.should == [
      [], "OP_1",
      [1], "OP_IF",
      [], "OP_2",
      [2], "OP_ELSE",
      [2], "OP_ENDIF",
      [2], "OP_2",
      [2, 2], "OP_EQUAL",
      [1], "RESULT"]

    script = Bitcoin::Script.from_string("0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_2 OP_EQUAL")
    script.run {}
    script.debug.should == [
      [], "OP_0",
      [[""]], "OP_IF",
      [], "OP_ELSE",
      [], "OP_3",
      [3], "OP_ENDIF",
      [3], "OP_2",
      [3, 2], "OP_EQUAL",
      [0], "RESULT"]

    script = Bitcoin::Script.from_string("0 OP_IF deadbeef OP_ELSE OP_3 OP_ENDIF OP_2 OP_EQUAL")
    script.run {}
    script.debug.should == [
      [], "OP_0",
      [[""]], "OP_IF",
      [], "OP_ELSE",
      [], "OP_3",
      [3], "OP_ENDIF",
      [3], "OP_2",
      [3, 2], "OP_EQUAL",
      [0], "RESULT"]

    script = Bitcoin::Script.from_string("1 OP_IF 2 OP_ELSE 3 OP_ENDIF 2 OP_EQUAL")
    script.run {}
    script.debug.should ==  [[], "OP_1", [1], "OP_IF", [], "OP_2", [2], "OP_ELSE", [2], "OP_ENDIF", [2], "OP_2", [2, 2], "OP_EQUAL", [1], "RESULT"]

    script = Bitcoin::Script.from_string("
0
3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501
304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301
1
635221022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc2102ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd52ae675221025182b1ca9a1ea9358f61cb363ac80c80b145204d9c4d875c35873d3d578853
OP_IF
2
022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc
02ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd
2
OP_CHECKMULTISIG
OP_ELSE
2
025182b1ca9a1ea9358f61cb363ac80c80b145204d9c4d875c35873d3d57885348
02b18808b3e6857e396167890a52f898cbd5215354f027b89fed895058e49a158b
2
OP_CHECKMULTISIG
OP_ENDIF")
    script.run {}
    script.debug.should == [
      [], "OP_0",
      [[""]], "PUSH DATA 3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"]], "PUSH DATA 304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"]], "OP_1",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1], "PUSH DATA 635221022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc2102ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd52ae675221025182b1ca9a1ea9358f61cb363ac80c80b145204d9c4d875c35873d3d578853",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1, ["635221022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc2102ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd52ae675221025182b1ca9a1ea9358f61cb363ac80c80b145204d9c4d875c35873d3d578853"]], "OP_IF",

      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1], "OP_2",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1, 2], "PUSH DATA 022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1, 2, ["022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc"]], "PUSH DATA 02ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1, 2, ["022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc"], ["02ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd"]], "OP_2",
      [[""], ["3045022041ccefcad804c28fcd843afeb10df3bd09d93e56542cda4ae9bcac18ed69f6c7022100f24d891b69695099a66b81a4ef382ff0ef388ad211505cd32e2ad3adebe5f74501"], ["304502201124a34c8bcc6a41c9bda088bc28e4274af02872866fa926205b0799e0f3b28a022100d0bbe8382a4e6ff46968bb8c2990bb63ef7f413f5b7c3912b4948b3eb0e72fc301"], 1, 2, ["022d73c0041da9794fcaa7286fcce35e126f84f8b53563be6abb3b213f964bfbfc"], ["02ab2445a289939e49e326dd29ca068cb38d1c9ef7618b7272d14c79c1abdea5cd"], 2], "OP_CHECKMULTISIG",
      [[""], 0], "OP_ELSE",
      [[""], 0], "OP_ENDIF",
      [[""], 0], "RESULT"]
  end

  it "should not execute p2sh recursively" do
    # this script_sig includes a pattern that matches the p2sh template
    script_sig = "0 a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87"
    pk_script = "OP_HASH160 92a04bc86e23f169691bd6926d11853cc61e1852 OP_EQUAL"
    script = Bitcoin::Script.from_string(script_sig + " " + pk_script)
    script.run.should == true
  end

  def build_p2sh_multisig_tx(m, *keys)
    redeem_script = Bitcoin::Script.to_multisig_script(m, *keys.map(&:pub))
    p2sh_address = Bitcoin.hash160_to_p2sh_address(Bitcoin.hash160(redeem_script.hth))

    prev_tx = build_tx {|t| t.input {|i| i.coinbase}
      t.output {|o| o.to p2sh_address; o.value 50e8 } }
    tx = build_tx {|t| t.input {|i| i.prev_out prev_tx, 0 }
      t.output {|o| o.to Bitcoin::Key.generate.addr; o.value 50e8 } }

    sig_hash = tx.signature_hash_for_input(0, redeem_script)
    return prev_tx, tx, redeem_script, sig_hash
  end

  it "#sort_p2sh_multisig_signatures 3-of-3" do
    keys = 3.times.map { Bitcoin::Key.generate }

    prev_tx, tx, redeem_script, sig_hash = build_p2sh_multisig_tx(3, *keys)
    sigs = keys.map {|k| k.sign(sig_hash) }

    # add sigs in all possible orders, sort them, and see if they are valid
    [0, 1, 2].permutation do |order|
      script_sig = Script.to_p2sh_multisig_script_sig(redeem_script)
      order.each{|i| script_sig = Script.add_sig_to_multisig_script_sig(sigs[i], script_sig)}
      script_sig = Script.sort_p2sh_multisig_signatures(script_sig, sig_hash)
      tx.in[0].script_sig = script_sig
      tx.verify_input_signature(0, prev_tx).should == true
    end
  end

  it "#sort_p2sh_multisig_signatures 2-of-3" do
    keys = 3.times.map { Bitcoin::Key.generate }

    prev_tx, tx, redeem_script, sig_hash = build_p2sh_multisig_tx(2, *keys)
    sigs = keys.map {|k| k.sign(sig_hash) }

    # add sigs in all possible orders, sort them, and see if they are valid
    [0, 1, 2].permutation(2) do |order|
      script_sig = Script.to_p2sh_multisig_script_sig(redeem_script)
      order.each{|i| script_sig = Script.add_sig_to_multisig_script_sig(sigs[i], script_sig)}
      script_sig = Script.sort_p2sh_multisig_signatures(script_sig, sig_hash)
      tx.in[0].script_sig = script_sig
      tx.verify_input_signature(0, prev_tx).should == true
    end
  end

end

describe "Implements BIP62" do
  it 'tests for incorrectly encoded S-values in signatures' do
    # TX 3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae
    sig_orig = ["304502210088984573e3e4f33db7df6aea313f1ce67a3ef3532ea89991494c7f018258371802206ceefc9291450dbd40d834f249658e0f64662d52a41cf14e20c9781144f2fe0701"].pack("H*")
    Bitcoin::Script::is_low_der_signature?(sig_orig).should == true

    # Set the start of the S-value to 0xff so it's well above the order of the curve divided by two
    sig = sig_orig.unpack("C*")
    length_r = sig[3]
    sig[6 + length_r] = 0xff

    Bitcoin::Script::is_low_der_signature?(sig.pack("C*")).should == false
  end
  it 'enforces rules 3 and 4' do
      Script.new([75].pack("C") + 'A' * 75).pushes_are_canonical?.should == true
      Script.new([Bitcoin::Script::OP_PUSHDATA1, 75].pack("CC") + 'A' * 75).pushes_are_canonical?.should == false
      Script.new([Bitcoin::Script::OP_PUSHDATA2, 255].pack("Cv") + 'A' * 255).pushes_are_canonical?.should == false
      Script.new([Bitcoin::Script::OP_PUSHDATA4, 1645].pack("CV") + 'A' * 1645).pushes_are_canonical?.should == false
    end
end

describe "Implements BIP66" do
  def build_crediting_tx(script_pk)
    tx = Bitcoin::P::Tx.new
    input = Bitcoin::P::TxIn.new(nil, 0xffffffff, 2, "\x00\x00")
    output = Bitcoin::P::TxOut.new(0, script_pk)
    tx.add_in(input)
    tx.add_out(output)
    Bitcoin::P::Tx.new(tx.to_payload)
  end

  def build_spending_tx(script_sig, tx_credit)
    tx = Bitcoin::P::Tx.new
    input = Bitcoin::P::TxIn.new(tx_credit.binary_hash, 0, 2, script_sig)
    output = Bitcoin::P::TxOut.new(0, '')
    tx.add_in(input)
    tx.add_out(output)
    Bitcoin::P::Tx.new(tx.to_payload)
  end

  # essentially DoTest() from script_tests.cpp
  def run_script_test(script_sig_str, script_pk_str, opts={})
    script_sig = Bitcoin::Script.from_string(script_sig_str)
    script_pk = Bitcoin::Script.from_string(script_pk_str)
    tx_credit = build_crediting_tx(script_pk.raw)
    tx = build_spending_tx(script_sig.raw, tx_credit)
    tx.verify_input_signature(0, tx_credit, Time.now.to_i, opts)
  end

  it 'overly long signature fails with DERSIG passes without' do
    script_sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'missing S fails with DERSIG passes without' do
    script_sig = "3022022000000000000000000000000000000000000000000000000000000000000000000"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'S with invalid fails with DERSIG passes without' do
    script_sig = "3024021077777777777777777777777777777777020a7777777777777777777777777777777701"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'non-integer R fails with DERSIG passes without' do
    script_sig = "302403107777777777777777777777777777777702107777777777777777777777777777777701"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'non-integer S fails with DERSIG passes without' do
    script_sig = "302402107777777777777777777777777777777703107777777777777777777777777777777701"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'zero length R fails with DERSIG passes without' do
    script_sig = "3014020002107777777777777777777777777777777701"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'zero length S fails with DERSIG passes without' do
    script_sig = "3014021077777777777777777777777777777777020001"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  it 'negative S fails with DERSIG passes without' do
    script_sig = "302402107777777777777777777777777777777702108777777777777777777777777777777701"
    script_pk = "0 OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
    run_script_test(script_sig, script_pk).should == true
  end

  # see: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki#examples
  # see also: https://github.com/bitcoin/bitcoin/pull/5713/files
  P1 = "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508"
  P2 = "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640"

  # Example 1: S1' P1 CHECKSIG (fails w/ verify_dersig, passes w/o)
  it 'example 1' do
    script_sig = "30440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201"
    script_pk = "#{P1} OP_CHECKSIG"
    run_script_test(script_sig, script_pk).should == true
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 2: S1' P1 CHECKSIG NOT (fails with either)
  it 'example 2' do
    script_sig = "304402208e43c0b91f7c1e5bc58e41c8185f8a6086e111b0090187968a86f2822462d3c902200a58f4076b1133b18ff1dc83ee51676e44c60cc608d9534e0df5ace0424fc0be01"
    script_pk = "#{P1} OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk).should == false
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 3: F P1 CHECKSIG fails (fails with either)
  it 'example 3' do
    script_sig = "0"
    script_pk = "#{P1} OP_CHECKSIG"
    run_script_test(script_sig, script_pk).should == false
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 4: F P1 CHECKSIG NOT (passes with either)
  it 'example 4' do
    script_sig = "0"
    script_pk = "#{P1} OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk).should == true
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == true
  end

  # Example 5: F' P1 CHECKSIG (fails with either)
  it 'example 5' do
    script_sig = "1"
    script_pk = "#{P1} OP_CHECKSIG"
    run_script_test(script_sig, script_pk).should == false
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 6: F' P1 CHECKSIG NOT (fails w/verify_dersig, passes w/o)
  it 'example 6' do
    script_sig = "1"
    script_pk = "#{P1} OP_CHECKSIG OP_NOT"
    run_script_test(script_sig, script_pk).should == true
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 7: 0 S1' S2 2 P1 P2 2 CHECKMULTISIG (fails w/verify_dersig, passes w/o)
  it 'example 7' do
    s1 = "30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501"
    s2 = "304402200b3d0b0375bb15c14620afa4aa10ae90a0d6a046ce217bc20fe0bc1ced68c1b802204b550acab90ae6d3478057c9ad24f9df743815b799b6449dd7e7f6d3bc6e274c01"
    script_sig = "0 #{s1} #{s2}"
    script_pk = "2 #{P1} #{P2} 2 OP_CHECKMULTISIG"
    run_script_test(script_sig, script_pk).should == true
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 8: 0 S1' S2 2 P1 P2 2 CHECKMULTISIG NOT (fails for either)
  it 'example 8' do
    s1 = "30440220f00a77260d34ec2f0c59621dc710f58169d0ca06df1a88cd4b1f1b97bd46991b02201ee220c7e04f26aed03f94aa97fb09ca5627163bf4ba07e6979972ec737db22601"
    s2 = "3044022079ea80afd538d9ada421b5101febeb6bc874e01dde5bca108c1d0479aec339a4022004576db8f66130d1df686ccf00935703689d69cf539438da1edab208b0d63c4801"
    script_sig = "0 #{s1} #{s2}"
    script_pk = "2 #{P1} #{P2} 2 OP_CHECKMULTISIG OP_NOT"
    run_script_test(script_sig, script_pk).should == false
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 9: 0 F S2' 2 P1 P2 2 CHECKMULTISIG fails (fails for either)
  it 'example 9' do
    s1 = "0"
    s2 = "3044022081aa9d436f2154e8b6d600516db03d78de71df685b585a9807ead4210bd883490220534bb6bdf318a419ac0749660b60e78d17d515558ef369bf872eff405b676b2e01"
    script_sig = "0 #{s1} #{s2}"
    script_pk = "2 #{P1} #{P2} 2 OP_CHECKMULTISIG"
    run_script_test(script_sig, script_pk).should == false
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 10: 0 F S2' 2 P1 P2 2 CHECKMULTISIG NOT (fails w/verify_dersig, passes w/o)
  it 'example 10' do
    s1 = "0"
    s2 = "30440220afa76a8f60622f813b05711f051c6c3407e32d1b1b70b0576c1f01b54e4c05c702200d58e9df044fd1845cabfbeef6e624ba0401daf7d7e084736f9ff601c3783bf501"
    script_sig = "0 #{s1} #{s2}"
    script_pk = "2 #{P1} #{P2} 2 OP_CHECKMULTISIG OP_NOT"
    run_script_test(script_sig, script_pk).should == true
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 11: 0 S1' F 2 P1 P2 2 CHECKMULTISIG (fails for either)
  it 'example 11' do
    s1 = "30440220cae00b1444babfbf6071b0ba8707f6bd373da3df494d6e74119b0430c5db810502205d5231b8c5939c8ff0c82242656d6e06edb073d42af336c99fe8837c36ea39d501"
    s2 = "0"
    script_sig = "0 #{s1} #{s2}"
    script_pk = "2 #{P1} #{P2} 2 OP_CHECKMULTISIG"
    run_script_test(script_sig, script_pk).should == false
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == false
  end

  # Example 12: 0 S1' F 2 P1 P2 2 CHECKMULTISIG NOT (passes for either)
  it 'example 12' do
    s1 = "30440220f00a77260d34ec2f0c59621dc710f58169d0ca06df1a88cd4b1f1b97bd46991b02201ee220c7e04f26aed03f94aa97fb09ca5627163bf4ba07e6979972ec737db22601"
    s2 = "0"
    script_sig = "0 #{s1} #{s2}"
    script_pk = "2 #{P1} #{P2} 2 OP_CHECKMULTISIG OP_NOT"
    run_script_test(script_sig, script_pk).should == true
    run_script_test(script_sig, script_pk, {verify_dersig: true}).should == true
  end
end
