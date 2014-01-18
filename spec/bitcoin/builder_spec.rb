# encoding: ascii-8bit

require_relative 'spec_helper'

include Bitcoin::Builder

describe "Bitcoin::Builder" do

  before do
    Bitcoin.network = :spec
    @keys = 5.times.map { Bitcoin::Key.generate }
    @target = target = "00".ljust(64, 'f')
    @genesis = create_block("00"*32, false)
    @block = create_block(@genesis.hash, false, [], @keys[0])
  end

  it "should build blocks" do
    block = build_block(@target) do |b|
      b.prev_block @block.hash

      b.tx do |t|
        t.input {|i| i.coinbase "foobar" }

        t.output do |o|
          o.value 5000000000

          o.script do |s|
            s.type :address
            s.recipient @keys[0].addr
          end
        end
      end
    end

    block.hash[0..1].should == "00"
    block.ver.should == 1
    block.prev_block.should == @block.binary_hash.reverse
    block.tx.size.should == 1
    tx = block.tx[0]
    tx.in.size.should == 1
    tx.out.size.should == 1
    tx.in[0].script_sig.should == ["foobar"].pack("H*")

    tx.out[0].value.should == 5000000000
  end

  it "should build transactions with in/outputs and signatures" do
    tx = build_tx do |t|
      t.input do |i|
        i.prev_out @block.tx[0]
        i.prev_out_index 0
        i.signature_key @keys[0]
      end

      t.output do |o|
        o.value 123

        o.script do |s|
          s.type :address
          s.recipient @keys[1].addr
        end
      end
    end

    tx.in[0].prev_out.reverse_hth.should == block.tx[0].hash
    tx.in[0].prev_out_index.should == 0
    Bitcoin::Script.new(tx.in[0].script_sig).chunks[1].unpack("H*")[0].should == @keys[0].pub

    tx.out[0].value.should == 123
    script = Bitcoin::Script.new(tx.out[0].pk_script)
    script.type.should == :hash160
    script.get_address.should == @keys[1].addr

    tx.verify_input_signature(0, block.tx[0]).should == true


    # check shortcuts also work
    tx2 = build_tx do |t|
      t.input {|i| i.prev_out @block.tx[0], 0; i.signature_key @keys[0] }
      t.output {|o| o.value 123; o.script {|s| s.recipient @keys[1].addr } }
    end
    tx2.in[0].prev_out.should == tx.in[0].prev_out
    tx2.in[0].prev_out_index.should == tx.in[0].prev_out_index
    tx2.out[0].value.should == tx.out[0].value
    tx2.out[0].pk_script.should == tx.out[0].pk_script
  end

  it "should build unsigned transactions and add the signature hash" do
    tx = build_tx do |t|
      t.input do |i|
        i.prev_out @block.tx[0]
        i.prev_out_index 0
        # no signature key
      end
      t.output do |o|
        o.value 123
        o.script {|s| s.recipient @keys[1].addr }
      end
    end

    tx.is_a?(Bitcoin::P::Tx).should == true
    tx.in[0].sig_hash.should != nil
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
