require_relative 'spec_helper'

include Bitcoin::Builder

describe "Bitcoin::Builder" do

  it "should build blocks and transactions with in/outputs and signatures" do

    keys = []
    5.times { keys << Bitcoin::Key.generate }

    target = "00".ljust(32, 'f')

    block = blk(target) do |b|
      b.prev_block "\x00"*32

      b.tx do |t|
        t.input {|i| i.coinbase "foobar" }

        t.output do |o|
          o.value 5000000000

          o.script do |s|
            s.type :address
            s.recipient keys[0].addr
          end
        end
      end
    end

    block.hash[0..1].should == "00"
    block.ver.should == 1
    block.prev_block.should == "\x00"*32
    block.tx.size.should == 1
    tx = block.tx[0]
    tx.in.size.should == 1
    tx.out.size.should == 1
    tx.in[0].script_sig.should == ["foobar"].pack("H*")

    tx.out[0].value.should == 5000000000

    tx = tx do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end

      t.output do |o|
        o.value 123

        o.script do |s|
          s.type :address
          s.recipient keys[1].addr
        end
      end
    end

    tx.in[0].prev_out.reverse.unpack("H*")[0].should == block.tx[0].hash
    tx.in[0].prev_out_index.should == 0
    Bitcoin::Script.new(tx.in[0].script_sig).chunks[1].unpack("H*")[0].should == keys[0].pub

    tx.out[0].value.should == 123
    script = Bitcoin::Script.new(tx.out[0].pk_script)
    script.type.should == :hash160
    script.get_address.should == keys[1].addr

    tx.verify_input_signature(0, block.tx[0]).should == true
  end

  it "should build address script" do
    key = Bitcoin::Key.generate
    s = script {|s| s.type :address; s.recipient key.addr }
    Bitcoin::Script.new(s).to_string.should ==
      "OP_DUP OP_HASH160 #{Bitcoin.hash160_from_address(key.addr)} OP_EQUALVERIFY OP_CHECKSIG"
  end

  it "should build pubkey script" do
    key = Bitcoin::Key.generate
    s = script {|s| s.type :pubkey; s.recipient key.pub }
    Bitcoin::Script.new(s).to_string.should == "#{key.pub} OP_CHECKSIG"
  end

  it "should build multisig script" do
    keys = 3.times.map { Bitcoin::Key.generate }
    s = script {|s| s.type :multisig; s.recipient 1, keys[0].pub, keys[1].pub }
    Bitcoin::Script.new(s).to_string.should == "1 #{keys[0].pub} #{keys[1].pub} 2 OP_CHECKMULTISIG"
  end

end
