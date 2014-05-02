# encoding: ascii-8bit

require_relative '../spec_helper.rb'
require 'bitcoin/script'

describe "Bitcoin::Script OPCODES" do

  before do
    @script = Bitcoin::Script.new("")
    @script.class.instance_eval { attr_accessor :stack, :stack_alt }
  end

  def op(op, stack)
    @script.stack = stack
    @script.send("op_#{op}")
    @script.stack
  end

  it "should do OP_NOP" do
    op(:nop, ["foobar"]).should == ["foobar"]
  end

  it "should do OP_DUP" do
    op(:dup, ["foobar"]).should == ["foobar", "foobar"]
  end

  it "should do OP_SHA256" do
    op(:sha256, ["foobar"]).should == [["c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"].pack("H*")]
  end

  it "should do OP_SHA1" do
    op(:sha1, ["foobar"]).should == [["8843d7f92416211de9ebb963ff4ce28125932878"].pack("H*")]
  end

  it "should do OP_HASH160" do
    op(:hash160, ["foobar"]).should == [["f6c97547d73156abb300ae059905c4acaadd09dd"].pack("H*")]
  end

  it "should do OP_RIPEMD160" do
    op(:ripemd160, ["foobar"]).should == [["a06e327ea7388c18e4740e350ed4e60f2e04fc41"].pack("H*")]
  end

  it "should do OP_HASH256" do
    op(:hash256, ["foobar"]).should == [["3f2c7ccae98af81e44c0ec419659f50d8b7d48c681e5d57fc747d0461e42dda1"].pack("H*")]
  end

  it "should do OP_TOALTSTACK" do
    op(:toaltstack, ["foobar"]).should == []
    @script.stack_alt.should == ["foobar"]
  end

  it "should do OP_FROMALTSTACK" do
    @script.instance_eval { @stack     = [] }
    @script.instance_eval { @stack_alt = ["foo"] }
    @script.op_fromaltstack
    @script.stack.should == ["foo"]
    @script.stack_alt.should == []
  end

  it "should do OP_TUCK" do
    op(:tuck, ["foobar", "foo", "bar"]).should == ["foobar", "bar", "foo", "bar"]
  end

  it "should do OP_SWAP" do
    op(:swap, ["foo", "bar"]).should == ["bar", "foo"]
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
    op(:sub, [3, 2]).should == [1]
    op(:sub, [9, 1]).should == [8]
    op(:sub, [1, 3]).should == [-2]
  end

  it "should do OP_GREATERTHANOREQUAL" do
    op(:greaterthanorequal, [2, 1]).should == [1]
    op(:greaterthanorequal, [2, 2]).should == [1]
    op(:greaterthanorequal, [1, 2]).should == [0]
  end

  it "should do OP_DROP" do
    op(:drop, ["foo"]).should == []
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
    op("0", ["foo"]).should == ["foo", ""]
  end

  it "should do OP_1" do
    op("1", ["foo"]).should == ["foo", 1]
  end

  it "should do OP_MIN" do
    [
      [[4, 5], 4],
      [[5, 4], 4],
      [[4, 4], 4],
      [["\x04", "\x05"], 4],

      [[1, 0], 0],
      [[0, 1], 0],
      [[-1, 0], -1],
      [[0, -2147483647], -2147483647],
    ].each{|stack, expected|
      op(:min, stack).should == [expected]
    }
  end

  it "should do OP_MAX" do
    [
      [[4, 5], 5],
      [[5, 4], 5],
      [[4, 4], 4],
      [["\x04", "\x05"], 5],

      [[2147483647, 0], 2147483647],
      [[0, 100], 100],
      [[-100, 0], 0],
      [[0, -2147483647], 0],
    ].each{|stack, expected|
      op(:max, stack).should == [expected]
    }
  end

  it "should do op_2over" do
    op('2over', [1,2,3,4]).should == [1,2,3,4,1,2]
  end

  it "should do op_2swap" do
    op("2swap", [1,2,3,4]).should == [3,4,1,2]
  end

  it "should do op_ifdup" do
    op(:ifdup, [1]).should == [1,1]
    op(:ifdup, ['a']).should == ['a','a']
    op(:ifdup, [0]).should == [0]
  end

  it "should do op_1negate" do
    op("1negate", []).should == [ -1 ]
  end

  it "should do op_depth" do
    op(:depth, []).should == [0]
    op(:depth, [1,2,3]).should == [1,2,3,3]
  end

  it "should do op_boolor" do
    [
      [[ 1,  1], 1],
      [[ 1,  0], 1],
      [[ 0,  1], 1],
      [[ 0,  0], 0],
      [[16, 17], 1],
      [[-1,  0], 1],
      #[[1     ], :invalid],
    ].each{|stack, expected|
      op(:boolor, stack).should == [ expected ]
    }
  end

  it "should do op_lessthan" do
    [
      [[ 11, 10], 0],
      [[  4,  4], 0],
      [[ 10, 11], 1],
      [[-11, 11], 1],
      [[-11,-10], 1],
      [[ -1,  0], 1],
    ].each{|stack, expected|
      op(:lessthan, stack).should == [ expected ]
    }
  end

  it "should do op_lessthanorequal" do
    [
      [[ 11, 10], 0],
      [[  4,  4], 1],
      [[ 10, 11], 1],
      [[-11, 11], 1],
      [[-11,-10], 1],
      [[ -1,  0], 1],
    ].each{|stack, expected|
      op(:lessthanorequal, stack).should == [ expected ]
    }
  end

  it "should do op_greaterthan" do
    [
      [[ 11, 10], 1],
      [[  4,  4], 0],
      [[ 10, 11], 0],
      [[-11, 11], 0],
      [[-11,-10], 0],
      [[ -1,  0], 0],
      [[  1,  0], 1],
    ].each{|stack, expected|
      op(:greaterthan, stack).should == [expected]
    }
  end

  it "should do op_greaterthanorequal" do
    [
      [[ 11, 10], 1],
      [[  4,  4], 1],
      [[ 10, 11], 0],
      [[-11, 11], 0],
      [[-11,-10], 0],
      [[ -1,  0], 0],
      [[  1,  0], 1],
      [[  0,  0], 1],
    ].each{|stack, expected|
      op(:greaterthanorequal, stack).should == [expected]
    }
  end

  it "should do op_not" do
    op(:not, [0]).should == [1]
    op(:not, [1]).should == [0]
  end

  it "should do op_0notequal" do
    [
      [[0],    0],
      [[1],    1],
      [[111],  1],
      [[-111], 1],
    ].each{|stack, expected|
      op("0notequal", stack).should == [expected]
    }
  end

  it "should do op_abs" do
    [
      [[0],     0],
      [[16],   16],
      [[-16],  16],
      [[-1],    1],
    ].each{|stack, expected|
      op(:abs, stack).should == [expected]
    }
  end

  it "should do op_2div" do
    op("2div", [  2]).should == [ 1]
    op("2div", [ 10]).should == [ 5]
    op("2div", [-10]).should == [-5]
  end

  it "should do op_2mul" do
    op("2mul", [  2]).should == [  4]
    op("2mul", [ 10]).should == [ 20]
    op("2mul", [-10]).should == [-20]
  end

  it "should do op_1add" do
    op("1add", [  2]).should == [ 3]
    op("1add", [ 10]).should == [11]
    op("1add", [-10]).should == [-9]
  end

  it "should do op_1sub" do
    op("1sub", [  2]).should == [  1]
    op("1sub", [ 10]).should == [  9]
    op("1sub", [-10]).should == [-11]
  end

  it "should do op_negate" do
    op("negate", [-2]).should == [ 2]
    op("negate", [ 2]).should == [-2]
    op("negate", [ 0]).should == [ 0]
  end

  it "should do op_within" do
    [
      [[0, 0, 1],  1],
      [[1, 0, 1],  0],
      [[0, -2147483647, 2147483647],  1],
      [[-1, -100, 100],  1],
      [[11, -100, 100],  1],
      [[-2147483647, -100, 100],  0],
      [[2147483647, -100, 100],  0],
      [[-1, -1, 0],  1],
    ].each{|stack, expected|
      op(:within, stack).should == [expected]
    }
  end

  it "should do op_numequal" do
    [
      [[0, 0],  1],
      [[0, 1],  0],
    ].each{|stack, expected|
      op(:numequal, stack).should == [expected]
    }
  end

  it "should do op_numequalverify" do
    [
      [[0, 0],   []],
      [[0, 1],  [0]],
    ].each{|stack, expected|
      op(:numequalverify, stack).should == expected
    }
  end

  it "should do op_numnotequal" do
    [
      [[0, 0],  0],
      [[0, 1],  1],
    ].each{|stack, expected|
      op(:numnotequal, stack).should == [expected]
    }
  end

  it "should do op_over" do
    [
      [[1, 0],  [1,0,1]],
      [[-1, 1], [-1,1,-1]],
      [[1], [1]],
    ].each{|stack, expected|
      op(:over, stack).should == expected
    }
  end

  it "should do op_pick" do
    [
      [[1, 0, 0, 0, 3],  [1,0,0,0,1]],
      [[1, 0],  [1,1]],
    ].each{|stack, expected|
      op(:pick, stack).should == expected
    }
  end

  it "should do op_roll" do
    [
      [[1, 0, 0, 0, 3],  [0,0,0,1]],
      [[1, 0],  [1]],
    ].each{|stack, expected|
      op(:roll, stack).should == expected
    }
  end

  it "should do op_rot" do
    op(:rot, [22, 21, 20]).should == [21, 20, 22]
    op(:rot, [21, 20]).should == [21, 20]
  end

  it "should do op_2drop" do
    op('2drop', [1,2,3]).should == [1]
    op('2drop', [  2,3]).should == [ ]
  end

  it "should do op_2dup" do
    op('2dup', [2,3]).should == [2,3,2,3]
    op('2dup', [3  ]).should == [  3    ]
  end

  it "should do op_3dup" do
    op('3dup', [1,2,3]).should == [1,2,3,1,2,3]
    op('3dup', [  2,3]).should == [  2,3      ]
    op('3dup', [    3]).should == [    3      ]
  end

  it "should do op_nip" do
    op(:nip, [1,2]).should == [2]
    op(:nip, [1,2,3]).should == [1,3]
  end

  it "should do op_size" do
    [
      [[0],    [0,0]],
      [[1],    [1,1]],
      [[127],  [127,1]],
      [[128],  [128,2]],
      [[32767],  [32767,2]],
      [[32768],  [32768,3]],
      [[8388607],  [8388607,3]],
      [[8388608],  [8388608,4]],
      [[2147483647],  [2147483647,4]],
      [[2147483648],  [2147483648,5]],
      [[-1],  [-1,1]],
      [[-127],  [-127,1]],
      [[-128],  [-128,2]],
      [[-32767],  [-32767,2]],
      [[-32768],  [-32768,3]],
      [[-8388607],  [-8388607,3]],
      [[-8388608],  [-8388608,4]],
      [[-2147483647],  [-2147483647,4]],
      [[-2147483648],  [-2147483648,5]],
      [["abcdefghijklmnopqrstuvwxyz"],  ["abcdefghijklmnopqrstuvwxyz",26]],
    ].each{|stack, expected|
      op(:size, stack).should == expected
    }
  end

  it "should do if/notif/else/end" do
    [
      "1 1 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF",
      "1 0 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF",
      "1 1 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF",
      "0 0 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF",
      "1 1 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF",
      "1 0 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF",
      "1 0 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF",
      "0 1 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF",
      "0 OP_IF OP_RETURN OP_ENDIF 1",
      "1 OP_IF 1 OP_ENDIF",
      "0 OP_IF 50 OP_ENDIF 1",
      "0 OP_IF OP_VER OP_ELSE 1 OP_ENDIF",
      "0 OP_IF 50 40 OP_ELSE 1 OP_ENDIF",
      "1 OP_DUP OP_IF OP_ENDIF",
      "1 OP_IF 1 OP_ENDIF",
      "1 OP_DUP OP_IF OP_ELSE OP_ENDIF",
      "1 OP_IF 1 OP_ELSE OP_ENDIF",
      "0 OP_IF OP_ELSE 1 OP_ENDIF",
    ].each{|script|
      Bitcoin::Script.from_string(script).run.should == true
    }
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

    @script.stack = [signature + hash_type, intger_pubkey=1]
    verify_callback = proc{|pub,sig,hash_type|
      pub.is_a?(String)
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
      k = Bitcoin::Key.new(nil, pk.unpack("H*")[0]) rescue false
      k && k.verify(hash, sig) rescue false
    end == true
  end

  it "should do OP_CHECKMULTISIG" do
    k1 = Bitcoin::Key.new; k1.generate
    k2 = Bitcoin::Key.new; k2.generate
    k3 = Bitcoin::Key.new; k3.generate
    sig1 = (k1.sign("foobar") + "\x01").unpack("H*")[0]
    sig2 = (k2.sign("foobar") + "\x01").unpack("H*")[0]
    sig3 = (k3.sign("foobar") + "\x01").unpack("H*")[0]

    script = "0 #{sig1} 1 #{k1.pub} 1 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == true

    script = "0 #{sig1} #{sig2} 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == true

    script = "0 #{sig2} #{sig1} 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

    script = "0 #{sig1} #{sig2} 2 #{k2.pub} #{k1.pub} 2 OP_CHECKMULTISIG"
    run_script(script, "foobar").should == false

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

    script = "0 #{sig1} f0f0f0f0 #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG OP_NOT"
    run_script(script, "foobar").should == true

    script = "1 1 1 1 1 OP_CHECKMULTISIG OP_NOT"
    run_script(script, "foobar").should == true

    # mainnet tx output: 514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58
    script = "0 #{sig1} 1 0 #{k1.pub} OP_SWAP OP_1ADD OP_CHECKMULTISIG"
    run_script(script, "foobar").should == true
    Bitcoin::Script.from_string(script).get_addresses.should == []
    Bitcoin::Script.from_string(script).is_multisig?.should == false
    script = "#{k1.pub} OP_SWAP OP_1ADD OP_CHECKMULTISIG"
    Bitcoin::Script.from_string(script).get_addresses.should == []
    Bitcoin::Script.from_string(script).is_multisig?.should == false

    # # TODO: check signature order; these assertions should fail:
    # script = "0 #{sig2} #{sig1} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    # run_script(script, "foobar").should == false
    # script = "0 #{sig3} #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    # run_script(script, "foobar").should == false
    # script = "0 #{sig1} #{sig3} #{sig2} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    # run_script(script, "foobar").should == false
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

    script = Bitcoin::Script.from_string("0 #{sig} #{inner_script} OP_HASH160 #{script_hash} OP_EQUAL")
    script.is_p2sh?.should == true
    run_script(script.to_string, "foobar").should == true

    script = Bitcoin::Script.from_string("OP_HASH160 #{script_hash} OP_EQUAL")
    script.is_p2sh?.should == true
    run_script(script.to_string, "foobar").should == false

    address = "3CkxTG25waxsmd13FFgRChPuGYba3ar36B"
    script = Bitcoin::Script.new(Bitcoin::Script.to_address_script(address))
    script.type.should == :p2sh

    inner_script = Bitcoin::Script.from_string("0 OP_NOT").raw.unpack("H*")[0]
    script_hash = Bitcoin.hash160(inner_script)
    script = Bitcoin::Script.from_string("#{inner_script} OP_HASH160 #{script_hash} OP_EQUAL")
    script.is_p2sh?.should == true
    run_script(script.to_string, "foobar").should == true
  end

  it "should skip OP_EVAL" do
    Bitcoin::Script.from_string("1 OP_EVAL").to_string.should == "1 OP_NOP1"
    Bitcoin::Script.from_string("1 OP_EVAL").run.should == true
    Bitcoin::Script.from_string("0 OP_EVAL").run.should == false
  end

  it "should do testnet3 scripts" do
    [
      "OP_1NEGATE OP_1NEGATE OP_ADD 82 OP_EQUAL",
      "6f 1 OP_ADD 12 OP_SUB 64 OP_EQUAL",
      "76:1:07 7 OP_EQUAL",
      "OP_1NEGATE e4 64 OP_WITHIN",
      "0 ffffffff ffffff7f OP_WITHIN",
      "6162636465666768696a6b6c6d6e6f707172737475767778797a OP_SIZE 1a OP_EQUAL",
      "0 OP_IFDUP OP_DEPTH 1 OP_EQUALVERIFY 0 OP_EQUAL",
      "1 OP_NOP1 OP_CHECKHASHVERIFY OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10 1 OP_EQUAL",
      "1 OP_NOP1 OP_NOP2 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10 1 OP_EQUAL",
      "0 ffffffff ffffff7f OP_WITHIN",
      "0:1:16 0:1:15 0:1:14 OP_ROT OP_ROT 0:1:15 OP_EQUAL",
      "ffffff7f OP_NEGATE OP_DUP OP_ADD feffffff80 OP_EQUAL",
      "90 OP_ABS 90 OP_NEGATE OP_EQUAL",
      "0 OP_DROP OP_DEPTH 0 OP_EQUAL",
      "1 0 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF",
      "6f OP_1SUB 6e OP_EQUAL",
      "13 14 OP_2DUP OP_ROT OP_EQUALVERIFY OP_EQUAL",
      "10 0 11 OP_TOALTSTACK OP_DROP OP_FROMALTSTACK OP_ADD 0:1:15 OP_EQUAL",
      "ffffff7f OP_DUP OP_ADD feffffff00 OP_EQUAL",
      "77:1:08 8 OP_EQUAL",
      "1 OP_NOT 0 OP_EQUAL",
      "0 OP_DROP OP_DEPTH 0 OP_EQUAL",
      "6f 1 OP_ADD 12 OP_SUB 64 OP_EQUAL",
      "0:1:0b 11 OP_EQUAL",
      "13 14 OP_2DUP OP_ROT OP_EQUALVERIFY OP_EQUAL",
      "ffffff7f OP_DUP OP_ADD feffffff00 OP_EQUAL",
      "0 OP_DROP OP_DEPTH 0 OP_EQUAL",
      "0 ffffffff OP_MIN ffffffff OP_NUMEQUAL",
      "90 OP_ABS 90 OP_NEGATE OP_EQUAL",
      "OP_1NEGATE e803 OP_ADD e703 OP_EQUAL",
      "0:1:16 0:1:15 0:1:14 OP_ROT OP_ROT OP_ROT 0:1:14 OP_EQUAL",
      "13 14 OP_2DUP OP_ROT OP_EQUALVERIFY OP_EQUAL",
      "8b 11 OP_LESSTHANOREQUAL",
      "ffffff7f ffffffff OP_ADD 0 OP_EQUAL",
      "ffffff7f OP_NEGATE OP_DUP OP_ADD feffffff80 OP_EQUAL",
      "8b 11 OP_GREATERTHANOREQUAL OP_NOT",
      "0 OP_0NOTEQUAL 0 OP_EQUAL",
      "2 82 OP_ADD 0 OP_EQUAL",
    ].each{|script|
      Bitcoin::Script.from_string(script).run.should == true
    }
  end

  it "should do OP_VER" do
    s = Bitcoin::Script.from_string("OP_VER"); s.run; s.invalid?.should == true
    s = Bitcoin::Script.from_string("1 OP_IF OP_VER 1 OP_ELSE 0 OP_ENDIF"); s.run.should == false; s.invalid?.should == true
    s = Bitcoin::Script.from_string("1 OP_IF 1 OP_ELSE OP_VER 0 OP_ENDIF"); s.run.should == true;  s.invalid?.should == false
  end

  it "should not allow DISABLED_OPCODES" do
    Bitcoin::Script::DISABLED_OPCODES.each{|opcode|
      s = Bitcoin::Script.from_string(Bitcoin::Script::OPCODES[opcode] + " 1"); s.run.should == false; s.invalid?.should == true
      s = Bitcoin::Script.from_string("1 OP_IF #{Bitcoin::Script::OPCODES[opcode]} 1 OP_ELSE 1 OP_ENDIF"); s.run.should == false; s.invalid?.should == true
      s = Bitcoin::Script.from_string("1 OP_IF 1 OP_ELSE #{Bitcoin::Script::OPCODES[opcode]} 1 OP_ENDIF"); s.run.should == false; s.invalid?.should == true
    }
  end

  it "check before casting and mark bad cases invalid" do
    s = Bitcoin::Script.from_string("OP_NOT") # tries to pop off an element from the empty stack here.
    s.run.should == false
    s.invalid?.should == true
  end

  it "should do OP_CHECKSIGVERIFY and OP_CHECKMULTISIGVERIFY" do
    tx1 = Bitcoin::P::Tx.new("0100000001a3fe4396b575690095bfc088d864aa971c99f65e2d893b48e0b26b1b60a28754000000006a47304402201ddfc8e3f825add9f42c0ce76dc5709cf76871e7ee6c97aae11d7db7f829b3f202201c3043515bfcf3d77845c8740ce4ccb4bda3f431da64f2596ee0ea2dfb727a5c01210328a5915165382c9b119d10d313c5781d98a7de79225f3c58e7fa115660ba90e0ffffffff0270f305000000000017a914ca164de1946bf0146ed1f32413df0efb0e1c730f87005d8806000000001976a91437c1d63690e00845663f3de661fef981c08e8de588ac00000000".htb)
    tx2 = Bitcoin::P::Tx.new("0100000001a1c5263304aa47f8e4e8a8dbca33e525667f7f0d84390c5a92d49eccbe5b970f00000000fde50152483045022100fbc7ccd87ad2384a4d8823d3cf36d839bb6acca3d80a9ed9c51c784b7bdf1e430220305fcb1660219fcc340935000aa92dd02684b763177b8a3c1be094c919af323701473044022008f66d2e31175cdefbd7461afb5f9946e5dcb8173d1a2d3ef837f1c810695d160220250354de77b4a919b87910aa203ecec54bd1006d2dad2fcac06a54f39a9d39a101514d4f0176519c6375522103b124c48bbff7ebe16e7bd2b2f2b561aa53791da678a73d2777cc1ca4619ab6f72103ad6bb76e00d124f07a22680e39debd4dc4bdb1aa4b893720dd05af3c50560fdd52af67529c63552103b124c48bbff7ebe16e7bd2b2f2b561aa53791da678a73d2777cc1ca4619ab6f721025098a1d5a338592bf1e015468ec5a8fafc1fc9217feb5cb33597f3613a2165e9210360cfabc01d52eaaeb3976a5de05ff0cfa76d0af42d3d7e1b4c233ee8a00655ed2103f571540c81fd9dbf9622ca00cfe95762143f2eab6b65150365bb34ac533160432102bc2b4be1bca32b9d97e2d6fb255504f4bc96e01aaca6e29bfa3f8bea65d8865855af672103ad6bb76e00d124f07a22680e39debd4dc4bdb1aa4b893720dd05af3c50560fddada820a4d933888318a23c28fb5fc67aca8530524e2074b1d185dbf5b4db4ddb0642848868685174519c6351670068000000000170f30500000000001976a914bce2fe0e49630a996cb9fe611e6b9b7d1e4dc21188acb4ff6153".htb)
    tx2.verify_input_signature(0, tx1).should == true
  end


end
