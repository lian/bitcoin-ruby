require_relative '../spec_helper.rb'
require 'bitcoin/script'

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
    @script.stack.should == ["foobar"]
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

  it "should do OP_MIN" do
    [
      [4, 5], [5, 4], [4, 4]
    ].each{|s|
      @script.instance_eval { @stack = s }
      @script.op_min
      @script.stack.should == [4]
    }
  end

  it "should do OP_MAX" do
    [
      [4, 5], [5, 4], [5, 5]
    ].each{|s|
      @script.instance_eval { @stack = s }
      @script.op_max
      @script.stack.should == [5]
    }
  end
  
  it "should do op_2over" do
    @script.instance_eval { @stack = [1,2,3,4] }
    @script.op_2over
    @script.stack.should == [1,2,3,4,1,2]
  end
  
  it "should do op_2swap" do
    @script.instance_eval { @stack = [1,2,3,4] }
    @script.op_2swap
    @script.stack.should == [3,4,1,2]
  end
  
  it "should do op_ifdup" do
    @script.instance_eval { @stack = [1] }
    @script.op_ifdup
    @script.stack.should == [1,1]
    
    @script.instance_eval { @stack = ['a'] }
    @script.op_ifdup
    @script.stack.should == ['a','a']
    
    @script.instance_eval { @stack = [0] }
    @script.op_ifdup
    @script.stack.should == [0]
  end

  it "should do op_1negate" do
    @script.instance_eval { @stack = [] }
    @script.op_1negate
    @script.stack.should == [ -1 ]
  end
  
  it "should do op_depth" do
    @script.instance_eval { @stack = [] }
    @script.op_depth
    @script.stack.should == [0]
    
    @script.instance_eval { @stack = [1,2,3] }
    @script.op_depth
    @script.stack.should == [1,2,3,3]
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
    end == true
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

    script = "#{sig1} #{sig2} #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG" # without OP_NOP
    run_script(script, "foobar").should == true

    script = "0 #{sig2} 1 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == true

    script = "0 #{sig2} OP_TRUE #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == true

    script = "0 #{sig1} #{sig2} #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

    script = "0 #{sig1} #{sig2} #{sig3} 3 #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

    script = "0 #{sig1} #{sig2} #{sig3} 3 2 #{k3.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

    script = "0 #{sig1} #{sig2} #{sig3} 3 0 #{k3.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

    script = "0 #{sig1} #{sig2} 2 3 #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

    script = "0 #{sig1} #{sig2} 0 3 #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

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


  it "should do OP_CHECKHASHVERIFY" do # https://en.bitcoin.it/wiki/BIP_0017
    k1 = Bitcoin::Key.new; k1.generate
    k2 = Bitcoin::Key.new; k2.generate
    k3 = Bitcoin::Key.new; k2.generate
    sig1 = (k1.sign("foobar") + "\x01").unpack("H*")[0]
    sig2 = (k2.sign("foobar") + "\x01").unpack("H*")[0]
    sig3 = (k2.sign("foobar") + "\x01").unpack("H*")[0]


    # scriptSig: [signatures...] OP_CODESEPARATOR 1 [pubkey1] [pubkey2] 2 OP_CHECKMULTISIG
    # scriptPubKey: [20-byte-hash of {1 [pubkey1] [pubkey2] 2 OP_CHECKMULTISIG} ] OP_CHECKHASHVERIFY OP_DROP
    script = "1 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    script = "0 #{sig1} OP_CODESEPARATOR #{script} #{checkhash} OP_CHECKHASHVERIFY OP_DROP"
    run_script(script, "foobar").should == true

    script = "1 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    script = "0 #{sig1} OP_CODESEPARATOR #{script} #{checkhash} OP_NOP2 OP_DROP" # tests OP_NOP2 as OP_CHECKHASHVERIFY
    run_script(script, "foobar").should == true

    # invalid checkhashverify
    script = "1 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    script = "1 #{k1.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    script = "0 #{sig1} OP_CODESEPARATOR #{script} #{checkhash} OP_NOP2 OP_DROP" # tests OP_NOP2 as OP_CHECKHASHVERIFY
    run_script(script, "foobar").should == false


    # scriptSig: [signature] OP_CODESEPARATOR [pubkey] OP_CHECKSIG
    # scriptPubKey: [20-byte-hash of {[pubkey] OP_CHECKSIG} ] OP_CHECKHASHVERIFY OP_DROP
    script = "#{k1.pub} OP_CHECKSIG"
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    script = "#{sig1} OP_CODESEPARATOR #{script} #{checkhash} OP_CHECKHASHVERIFY OP_DROP"
    run_script(script, "foobar").should == true

    # invalid checkhashverify
    script = "#{k2.pub} OP_CHECKSIG"
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    script = "#{k1.pub} OP_CHECKSIG"
    script = "#{sig1} OP_CODESEPARATOR #{script} #{checkhash} OP_CHECKHASHVERIFY OP_DROP"
    run_script(script, "foobar").should == false

    # invalid signature in checksig
    script = "#{k1.pub} OP_CHECKSIG"
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    script = "#{sig2} OP_CODESEPARATOR #{script} #{checkhash} OP_CHECKHASHVERIFY OP_DROP"
    run_script(script, "foobar").should == false
  end

  it "should do P2SH" do
    k1 = Bitcoin::Key.new; k1.generate
    sig = (k1.sign("foobar") + "\x01").unpack("H*")[0]
    inner_script = Bitcoin::Script.from_string("#{k1.pub} OP_CHECKSIG").raw.unpack("H*")[0]
    script_hash = Bitcoin.hash160(inner_script)
    script = Bitcoin::Script.from_string("#{sig} #{inner_script} OP_HASH160 #{script_hash} OP_EQUAL")
    script.is_p2sh?.should == true
    run_script(script.to_string, "foobar").should == true
    run_script(script.to_string, "barbaz").should == false

    script = Bitcoin::Script.from_string("OP_HASH160 #{script_hash} OP_EQUAL")
    script.is_p2sh?.should == true
    run_script(script.to_string, "foobar").should == false

    address = "3CkxTG25waxsmd13FFgRChPuGYba3ar36B"
    script = Bitcoin::Script.new(Bitcoin::Script.to_address_script(address))
    script.type.should == :p2sh
  end

end
