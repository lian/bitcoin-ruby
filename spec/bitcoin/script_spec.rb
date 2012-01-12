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

    Bitcoin::Script.new([123].pack("C")).to_string.should == "(opcode 123)"
    Bitcoin::Script.new([176].pack("C")).to_string.should == "OP_EVAL"

    # Bitcoin::Script.from_string("(opcode 123)").to_string.should == "(opcode 123)"
    # Bitcoin::Script.from_string("1 OP_DROP 2").to_string.should == "1 OP_DROP 2"
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

    Bitcoin::Script.from_string("0 OP_DROP 2 3 4").to_string.should == "0 OP_DROP 2 3 4"

    Bitcoin::Script.from_string("OP_EVAL").to_string.should == "OP_EVAL"
    Bitcoin::Script.from_string("OP_NOP1").to_string.should == "OP_EVAL" # test opcodes_alias table
    Bitcoin::Script.from_string("OP_NOP").to_string.should == "OP_NOP"
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
    Bitcoin::Script.from_string("OP_DUP OP_HASH160 0 OP_EQUALVERIFY OP_CHECKSIG")
      .get_hash160.should == nil
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
    Bitcoin::Script.from_string("OP_DUP OP_HASH160 0 OP_EQUALVERIFY OP_CHECKSIG")
      .is_hash160?.should == false
  end

  it '#run' do
    script = @script[1] + @script[0]
    Bitcoin::Script.new(script).run.should == true

    Bitcoin::Script.from_string("1 OP_DUP OP_DROP 1 OP_EQUAL")
      .run.should == true
    Bitcoin::Script.from_string("1 OP_DUP OP_DROP 1 OP_EQUAL")
      .run.should == true
    Bitcoin::Script.from_string("foo OP_DUP OP_DROP foo OP_EQUAL")
      .run.should == true
    Bitcoin::Script.from_string("bar foo OP_DUP OP_DROP bar OP_EQUAL")
      .run.should == false

    Bitcoin::Script.from_string("1 OP_DROP 2").run.should == false
  end

  it "should generate address script" do
    Bitcoin::Script.to_address_script('16Tc7znw2mfpWcqS84vBFfJ7PyoeHaXSz9')
      .should == ["76a9143be0c2daaabbf3d53e47352c19d1e8f047e2f94188ac"].pack("H*")
    Bitcoin::Script.to_address_script('mr1jU3Adw2pkvxTLvQA4MKpXB9Dynj9cXF')
      .should == nil
  end

  it "should generate pubkey script" do
    sig = ["3045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec"].pack("H*")
    pub = ["04bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c"].pack("H*")
    Bitcoin::Script.to_signature_pubkey_script(sig, pub)
      .should == ["483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874edfe086ee0a08fec014104bc3e2b520d4be3e2651f2ba554392ea31edd69d2081186ab98acda3c4bf45e41a5f6e093277b774b5893347e38ffafce2b9e82226e6e0b378cf79b8c2eed983c"].pack("H*")
  end


  describe "Bitcoin::Script OPCODES" do

    before do
      @script = Bitcoin::Script.new("")
      @script.class.instance_eval { attr_accessor :stack, :stack_alt }
      @script.stack << "foobar"
    end

    def op(op, stack)
      @script.stack = stack
      @script.send("op_#{op}")
      @script.stack
    end

    it "should do OP_NOP" do
      @script.op_nop
      @script.stack.should == []
    end

    it "should do OP_DUP" do
      @script.op_dup
      @script.stack.should == ["foobar", "foobar"]
    end

    it "should do OP_SHA256" do
      @script.op_sha256
      @script.stack.should ==
        [["c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"].pack("H*")]
    end

    it "should do OP_SHA1" do
      @script.op_sha1
      @script.stack.should ==
        [["8843d7f92416211de9ebb963ff4ce28125932878"].pack("H*")]
    end

    it "should do OP_HASH160" do
      @script.op_hash160
      @script.stack.should ==
        [["f6c97547d73156abb300ae059905c4acaadd09dd"].pack("H*")]
    end

    it "should do OP_RIPEMD160" do
      @script.op_ripemd160
      @script.stack.should ==
        [["a06e327ea7388c18e4740e350ed4e60f2e04fc41"].pack("H*")]
    end

    it "should do OP_HASH256" do
      @script.op_hash256
      @script.stack.should ==
        [["3f2c7ccae98af81e44c0ec419659f50d8b7d48c681e5d57fc747d0461e42dda1"].pack("H*")]
    end

    it "should do OP_TOALTSTACK" do
      @script.op_toaltstack
      @script.stack.should == []
      @script.stack_alt.should == ["foobar"]
    end

    it "should do OP_FROMALTSTACK" do
      @script.instance_eval { @stack_alt << "barfoo" }
      @script.op_fromaltstack
      @script.stack.should == ["foobar", "barfoo"]
      @script.stack_alt.should == []
    end

    it "should do OP_TUCK" do
      @script.instance_eval { @stack += ["foo", "bar"] }
      @script.op_tuck
      @script.stack.should == ["foobar", "bar", "foo", "bar"]
    end

    it "should do OP_SWAP" do
      @script.instance_eval { @stack << "barfoo" }
      @script.op_swap
      @script.stack.should == ["barfoo", "foobar"]
    end

    it "should do OP_BOOLAND" do
      op(:booland, [0, 0]).should == [0]
      op(:booland, [0, 1]).should == [0]
      op(:booland, [1, 0]).should == [0]
      op(:booland, [1, 1]).should == [1]
    end

    it "should do OP_ADD" do
      op(:add, [0, 1]).should == [1]
      op(:add, [3, 4]).should == [7]
      op(:add, [5,-4]).should == [1]
    end

    it "should do OP_SUB" do
      op(:sub, [2, 3]).should == [1]
      op(:sub, [1, 9]).should == [8]
      op(:sub, [3, 1]).should == [-2]
    end

    it "should do OP_GREATERTHANOREQUAL" do
      op(:greaterthanorequal, [1, 2]).should == [1]
      op(:greaterthanorequal, [2, 2]).should == [1]
      op(:greaterthanorequal, [2, 1]).should == [0]
    end

    it "should do OP_DROP" do
      @script.op_drop
      @script.stack.should == []
    end

    it "should do OP_EQUAL" do
      op(:equal, [1,2]).should == [0]
      op(:equal, [1,1]).should == [1]
    end

    it "should do OP_VERIFY" do
      op(:verify, [1]).should == []
      op(:verify, [0]).should == [0]
    end

    it "should do OP_EQUALVERIFY" do
      op(:equalverify, [1,2]).should == [0]
      @script.invalid?.should == true
      op(:equalverify, [1,1]).should == []
      @script.invalid?.should == false
    end

    it "should do OP_0" do
      @script.op_0
      @script.stack.should == ["foobar", ""]
    end

    it "should do OP_1" do
      @script.op_1
      @script.stack.should == ["foobar", 1]
    end

    it "should do OP_CHECKSIG" do
      @script.stack = ["bar", "foo"]
      verify_callback = proc{|pubkey,signature,type|
        pubkey   .should == "foo"
        signature.should == "ba"
        type     .should == "r".ord
        true
      }
      @script.op_checksig(verify_callback).should == [1]

      @script.stack = ["bar", "foo"]
      verify_callback = proc{ true }
      @script.op_checksig(verify_callback).should == [1]

      @script.stack = ["bar", "foo"]
      verify_callback = proc{ false }
      @script.op_checksig(verify_callback).should == [0]

      @script.stack = ["foo"]
      verify_callback = proc{ false }
      @script.op_checksig(verify_callback).should == nil


      pubkey    = ["04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3"].pack("H*")
      signature = ["304402202c2fb840b527326f9bbc7ce68c6c196a368a38864b5a47681352c4b2f416f7ed02205c4801cfa8aed205f26c7122ab5a5934fcf7a2f038fd130cdd8bcc56bdde0a00"].pack("H*")
      hash_type = [1].pack("C")
      signature_data = ["20245059adb84acaf1aa942b5d8a586da7ba76f17ecb5de4e7543e1ce1b94bc3"].pack("H*")

      @script.stack = [signature + hash_type, pubkey]
      verify_callback = proc{|pub,sig,hash_type|
        pub     .should == pubkey
        sig     .should == signature
        hash_type.should == 1

        hash = signature_data
        Bitcoin.verify_signature( hash, sig, pub.unpack("H*")[0] )
      }
      @script.op_checksig(verify_callback).should == [1]


      @script.stack = [signature + hash_type, pubkey]
      verify_callback = proc{|pub,sig,hash_type|
        hash = "foo" + signature_data
        Bitcoin.verify_signature( hash, sig, pub.unpack("H*")[0] )
      }
      @script.op_checksig(verify_callback).should == [0]

      @script.stack = [signature + hash_type, pubkey]
      verify_callback = proc{|pub,sig,hash_type|
        hash = signature_data
        Bitcoin.verify_signature( hash, "foo", pub.unpack("H*")[0] )
      }
      @script.op_checksig(verify_callback).should == [0]

      @script.stack = [signature + hash_type, pubkey]
      verify_callback = proc{|pub,sig,hash_type|
        hash = signature_data
        Bitcoin.verify_signature( hash, sig, "foo" )
      }
      @script.op_checksig(verify_callback).should == [0]

      # Bitcoin::Key API
      key = Bitcoin::Key.new; key.generate
      sig = (key.sign("foobar") + "\x01").unpack("H*")[0]
      script = Bitcoin::Script.from_string("#{sig} #{key.pub} OP_CHECKSIG")
      script.run{|pk, sig, hash_type|
        k = Bitcoin::Key.new nil, pk.unpack("H*")[0]
        k.verify("foobar", sig)
      }.should == true
      script.stack.should == []
    end


    def run_script(string, hash)
      script = Bitcoin::Script.from_string(string)
      script.run do |pk, sig, hash_type|
        k = Bitcoin::Key.new nil, pk.unpack("H*")[0]
        k.verify(hash, sig) rescue false
      end
    end

    it "should do OP_CHECKMULTISIG" do
      k1 = Bitcoin::Key.new; k1.generate
      k2 = Bitcoin::Key.new; k2.generate
      k3 = Bitcoin::Key.new; k3.generate
      sig1 = (k1.sign("foobar") + "\x01").unpack("H*")[0]
      sig2 = (k2.sign("foobar") + "\x01").unpack("H*")[0]
      sig3 = (k3.sign("foobar") + "\x01").unpack("H*")[0]

      script = "0 #{sig1} #{sig2} 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == true

      script = "0 #{sig1} #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == true

      script = "0 #{sig2} #{sig3} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == true

      script = "0 #{sig1} #{sig2} #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == true

      script = "0 #{sig2} f0f0f0f0 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == false

      script = "0 afafafaf #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == false

      script = "0 #{sig1} f0f0f0f0 #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      run_script(script, "foobar").should == false

      # # TODO: check signature order; these assertions should fail:
      # script = "0 #{sig2} #{sig1} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      # run_script(script, "foobar").should == false
      # script = "0 #{sig3} #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      # run_script(script, "foobar").should == false
      # script = "0 #{sig1} #{sig3} #{sig2} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
      # run_script(script, "foobar").should == false
    end

  end

end
