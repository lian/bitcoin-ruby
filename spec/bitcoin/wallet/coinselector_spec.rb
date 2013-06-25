# encoding: ascii-8bit

require_relative '../spec_helper'

include MiniTest
include Bitcoin::Wallet

describe Bitcoin::Wallet::SimpleCoinSelector do

  def txout_mock(value, next_in = true, in_block = true)
    tx, txout = Mock.new, Mock.new
    2.times { tx.expect(:get_block, in_block) }
    5.times { txout.expect(:value, value) }
    2.times do
      txout.expect(:get_next_in, next_in)
      txout.expect(:get_address, "addr")
      txout.expect(:get_tx, tx)
    end
    txout
  end

  it "should select only txouts which have not been spent" do
    txouts = [txout_mock(1000, nil), txout_mock(2000, nil),
      txout_mock(1000), txout_mock(3000, nil)]
    cs = SimpleCoinSelector.new(txouts)
    cs.select(2000).should == txouts[0..1]
    cs.select(4000).should == [txouts[0], txouts[1], txouts[3]]
  end

  it "should select only txouts which are in a block" do
    txouts = [txout_mock(1000, nil, false), txout_mock(2000, nil),
      txout_mock(1000), txout_mock(3000, nil)]
    cs = SimpleCoinSelector.new(txouts)
    cs.select(2000).should == txouts[1..1]
    cs.select(4000).should == [txouts[1], txouts[3]]
  end

end
