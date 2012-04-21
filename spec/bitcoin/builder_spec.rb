require_relative 'spec_helper'

include Bitcoin::Builder

describe "Bitcoin::Builder" do

  it "should build blocks and transactions with in/outputs and signatures" do

    keys = []
    5.times { keys << Bitcoin::Key.generate }

    target = "00".ljust(32, 'f')

    block = blk(target) do
      prev_block "\x00"*32

      tx do
        input { coinbase "foobar" }

        output do
          value 5000000000

          script do
            type :address
            recipient keys[0].addr
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

    tx = tx do
      input do
        prev_out block.tx[0]
        prev_out_index 0
        signature_key keys[0]
      end

      output do
        value 123

        script do
          type :address
          recipient keys[1].addr
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

end
