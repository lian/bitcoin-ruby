require_relative '../spec_helper'

include MiniTest
include Bitcoin
include Bitcoin::Wallet

describe Bitcoin::Wallet::Wallet do

  def txout_mock(value, next_in)
    txout = Mock.new
    txout.expect(:value, value)
    txout.expect(:get_next_in, next_in)
  end

  before do
    @storage = Mock.new
    @keystore = Mock.new
    @key = Key.from_base58('5J2hn1E8KEXmQn5gqykzKotyCcHbKrVbe8fjegsfVXRdv6wwon8')
    @keystore.expect(:keys, [@key])
    @selector = MiniTest::Mock.new
    @wallet = Wallet.new(@storage, @keystore, @selector)
  end

  it "should get total balance" do
    @storage.expect(:get_txouts_for_address, [], ['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'])
    @wallet.get_balance.should == 0

    @storage.expect(:get_txouts_for_address, [txout_mock(5000, nil)],
      ['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'])
    @wallet.get_balance.should == 5000

    @storage.expect(:get_txouts_for_address, [txout_mock(5000, true), txout_mock(1000, nil)],
      ['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'])
    @wallet.get_balance.should == 1000
    @storage.verify; @keystore.verify
  end

  it "should get all addrs" do
    @wallet.addrs.should == ['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo']

    @keystore.expect(:keys, [@key, Key.generate])
    @wallet.addrs.size.should == 2
    @keystore.verify
  end

  it "should list all addrs with balances" do
    @storage.expect(:get_balance, 0, ['dcbc93494b38ae96b14b1cc080d2acb514b7e955'])
    @wallet.list.should == [['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo', 0]]

    @storage.expect(:get_balance, 5000, ['dcbc93494b38ae96b14b1cc080d2acb514b7e955'])
    @wallet.list.should == [['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo', 5000]]
    @storage.verify
  end

  it "should create new addr" do
    @wallet.addrs.size.should == 1

    key = Key.generate
    @keystore.expect(:new_key, key)
    @keystore.expect(:keys, [@key, key])
    a = @wallet.get_new_addr
    @wallet.addrs.size.should == 2
    @wallet.addrs[1].should == a
  end

  describe "Bitcoin::Wallet::Wallet#tx" do

    def txout_mock(value, next_in)
      txout = Mock.new
      txout.expect(:value, value)
      txout.expect(:get_next_in, next_in)
    end

    before do
      txout = txout_mock(5000, nil)
      tx = Mock.new
      tx.expect(:binary_hash, "foo")
      tx.expect(:out, [txout])
      txout.expect(:get_tx, tx)
      txout.expect(:get_address, "1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo")
      txout.expect(:pk_script,
        Script.to_address_script('1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'))
      @storage.expect(:get_txouts_for_address, [txout],
        ['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'])
      @keystore.expect(:key, @key, ['1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'])
      selector = Mock.new
      selector.expect(:select, [txout], [[txout]])
      @selector.expect(:new, selector, [[txout]])
      @tx = @wallet.tx([['1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]])
    end

    it "should have hash" do
      @tx.hash.size.should == 64
    end

    it "should have correct inputs" do
      @tx.in.size.should == 1
      @tx.in.first.prev_out.should == ("foo" + "\x00"*29)
      @tx.in.first.prev_out_index.should == 0
    end

    it "should have correct outputs" do
      @tx.out.size.should == 2
      @tx.out.first.value.should == 1000
      s = Script.new(@tx.out.first.pk_script)
      s.get_address.should == '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7'
    end

    it "should have change output" do
      @tx.out.last.value.should == 4000
      s = Script.new(@tx.out.last.pk_script)
      s.get_address.should == '1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'
    end

    it "should leave tx fee" do
      @tx = @wallet.tx([['1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]], 50)
      @tx.out.last.value.should == 3950
    end

    it "should send change to specified address" do
      @tx = @wallet.tx([['1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]], 50,
        '1EAntvSjkNeaJJTBQeQcN1ieU2mYf4wU9p')
      Script.new(@tx.out.last.pk_script).get_address.should ==
        '1EAntvSjkNeaJJTBQeQcN1ieU2mYf4wU9p'
    end

    it "should send change to new address" do
      key = Key.generate
      @keystore.expect(:new_key, key)
      @keystore.expect(:keys, [@key, key])
      @tx = @wallet.tx([['1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]], 50, :new)
      @wallet.addrs.size.should == 2
      @wallet.addrs.last.should == key.addr
      Script.new(@tx.out.last.pk_script).get_address.should == key.addr
    end

    it "should return nil if insufficient balance" do
      @tx = @wallet.tx([['1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 7000]])
      @tx.should == nil
    end
  end

  # it "should send tx" # TODO
  # it "should update txouts on new tx" (txouts, balance, list) # TODO: node callbacks

end
