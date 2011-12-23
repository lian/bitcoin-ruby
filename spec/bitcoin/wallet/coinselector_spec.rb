require_relative '../spec_helper'

include MiniTest
include Bitcoin::Wallet

describe Bitcoin::Wallet::SimpleCoinSelector do

  def txout_mock(value, next_in)
    txout = Mock.new
    txout.expect(:value, value)
    txout.expect(:get_next_in, next_in)
    txout.expect(:get_address, "addr")
    txout
  end

  it "should select txouts" do
    txouts = [txout_mock(1000, nil), txout_mock(2000, nil),
      txout_mock(1000, true), txout_mock(3000, nil)]
    cs = SimpleCoinSelector.new(txouts)
    cs.select(2000).should == txouts[0..1]
    cs.select(4000).should == [txouts[0], txouts[1], txouts[3]]
  end

end
