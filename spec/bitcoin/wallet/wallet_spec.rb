# encoding: ascii-8bit

require_relative '../spec_helper'
require 'json'
require 'fileutils'
include MiniTest
include Bitcoin
include Bitcoin::Wallet

def txout_mock(value, next_in = true, in_block = true)
  tx, txout = Mock.new, Mock.new
  tx.expect(:get_block, in_block)
  4.times { txout.expect(:value, value) }
  2.times { txout.expect(:get_next_in, next_in) }
  6.times { txout.expect(:hash, [value, next_in].hash) }
  txout.expect(:eql?, false, [1])
  txout.expect(:==, false, [1])
  txout.expect(:get_tx, tx)
end

describe Bitcoin::Wallet::Wallet do

  class DummyKeyStore

    def initialize keys
      @keys = keys.map{|k| { key: k, addr: k.addr } }
    end

    def key(addr)
      @keys.select{|k| k[:key].addr == addr }.first
    end

    def keys
      @keys
    end

    def new_key
      k=Bitcoin::Key.generate
      @keys << { key: k, addr: k.addr}
      @keys[-1]
    end
  end

  before do
    Bitcoin.network = :bitcoin
    @storage = Mock.new
    @key = Key.from_base58('5J2hn1E8KEXmQn5gqykzKotyCcHbKrVbe8fjegsfVXRdv6wwon8')
    @addr = '1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo'
    #@key2 = Key.from_base58('5KK9Lw8gtNd4kcaXQJmkwcmNy8Y5rLGm49RqhcYAb7qRhWxaWMJ')
    #@addr2 = '134A4Bi8jN5V2KjkwmXUHjokDqdyqZ778J'
    #@key3 = Key.from_base58('5JFcJByQvwYnWjQ2RHTTu6LLGiBj9oPQYsHqKWuKLDVAvv4cQ7E')
    #@addr3 = '1EnrPVaRiRgrs1D7pujYZNN1N6iD9unZV6'

    @storage.expect(:add_watched_address, [], [@addr])

    keystore_data = [{:addr => @key.addr, :priv => @key.priv, :pub => @key.pub}]
    file_stub = StringIO.new
    file_stub.write(keystore_data.to_json); file_stub.rewind
    @keystore = SimpleKeyStore.new(file: file_stub)
    @selector = MiniTest::Mock.new
    @wallet = Wallet.new(@storage, @keystore, @selector)
  end

  it "should get total balance" do
    @storage.expect(:class, Bitcoin::Storage::Backends::SequelStore, [])
    @storage.expect(:get_txouts_for_address, [], [@addr])
    2.times { @storage.expect(:class, Bitcoin::Storage::Backends::SequelStore, []) }
    @wallet.get_balance.should == 0

    @storage.expect(:get_txouts_for_address, [txout_mock(5000, nil)], [@addr])
    @wallet.get_balance.should == 5000

    @storage.expect(:get_txouts_for_address, [txout_mock(5000, true), txout_mock(1000, nil)],
      [@addr])
    @wallet.get_balance.should == 1000
  end

  it "should get all addrs" do
    @wallet.addrs.should == [@addr]
    @wallet.addrs.size.should == 1
  end

  it "should list all addrs with balances" do
    @storage.expect(:get_balance, 0, ['dcbc93494b38ae96b14b1cc080d2acb514b7e955'])
    list = @wallet.list
    list.size.should == 1
    list = list[0]
    list.size.should == 2
    list[0][:addr].should == "1M89ZeWtmZmATzE3b6PHTBi8c7tGsg5xpo"
    list[1].should == 0

    @storage.expect(:get_balance, 5000, ['dcbc93494b38ae96b14b1cc080d2acb514b7e955'])
    list = @wallet.list
    list.size.should == 1
    list = list[0]
    list.size.should == 2
    list[0][:addr].should == @addr
    list[1].should == 5000
  end

  it "should create new addr" do
    @wallet.addrs.size.should == 1

    @storage.expect(:add_watched_address, [], [String])
    a = @wallet.get_new_addr
    @wallet.addrs.size.should == 2
    @wallet.addrs[1].should == a
  end

  # describe "Bitcoin::Wallet::Wallet#tx" do

  #   before do
  #     txout = txout_mock(5000, nil)
  #     tx = Mock.new
  #     2.times { tx.expect(:binary_hash, "foo") }
  #     8.times { tx.expect(:out, [txout]) }
  #     3.times { tx.expect(:get_block, true) }
  #     5.times { txout.expect(:get_tx, tx) }
  #     6.times { txout.expect(:get_address, @addr) }
  #     8.times { txout.expect(:pk_script, Script.to_address_script(@addr)) }
  #     2.times { @storage.expect(:get_txouts_for_address, [txout], [@addr]) }
  #     2.times { @storage.expect(:class, Bitcoin::Storage::Backends::SequelStore, []) }
  #     selector = Bitcoin::Wallet::SimpleCoinSelector.new([txout])
  #     2.times { @selector.expect(:new, selector, [[txout]]) }
  #     @tx = @wallet.new_tx([[:address, '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]])
  #   end


  #   it "should have hash" do
  #     @tx.hash.size.should == 64
  #   end

  #   it "should have correct inputs" do
  #     @tx.in.size.should == 1
  #     @tx.in.first.prev_out.should == ("foo" + "\x00"*29)
  #     @tx.in.first.prev_out_index.should == 0
  #   end

  #   it "should have correct outputs" do
  #     @tx.out.size.should == 2
  #     @tx.out.first.value.should == 1000
  #     s = Script.new(@tx.out.first.pk_script)
  #     s.get_address.should == '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7'
  #   end

  #   it "should have change output" do
  #     @tx.out.last.value.should == 4000
  #     s = Script.new(@tx.out.last.pk_script)
  #     s.get_address.should == @addr
  #   end

  #   it "should leave tx fee" do
  #     @tx = @wallet.new_tx([[:address, '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]], 50)
  #     @tx.out.last.value.should == 3950
  #   end

  #   it "should send change to specified address" do
  #     @tx = @wallet.new_tx([[:address, '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]], 50,
  #       '1EAntvSjkNeaJJTBQeQcN1ieU2mYf4wU9p')
  #     Script.new(@tx.out.last.pk_script).get_address.should ==
  #       '1EAntvSjkNeaJJTBQeQcN1ieU2mYf4wU9p'
  #   end

  #   it "should send change to new address" do
  #     @tx = @wallet.new_tx([[:address, '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 1000]], 50, :new)
  #     @wallet.addrs.size.should == 2
  #     Script.new(@tx.out.last.pk_script).get_address.should == @wallet.addrs.last
  #   end

  #   it "should raise exception if insufficient balance" do
  #     -> {@tx = @wallet.new_tx([[:address, '1M2JjkX7KAgwMyyF5xc2sPSfE7mL1jqkE7', 7000]])}
  #     .should.raise(RuntimeError).message.should == "Insufficient funds."
  #   end


  #   it "should create unsigned tx" do
  #     Bitcoin.network = :spec
  #     @key = Bitcoin::Key.generate
  #     @key2 = Bitcoin::Key.generate
  #     @store = Storage.sequel(db: "sqlite:/")
  #     @store.log.level = :debug

  #     @keystore = SimpleKeyStore.new(file: StringIO.new("[]"))
  #     @wallet = Wallet.new(@store, @keystore, SimpleCoinSelector)

  #     @wallet.keystore.add_key(addr: @key.addr)

  #     @genesis = Bitcoin::P::Block.new("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000".htb)

  #     @store.new_block @genesis
  #     create_block(@genesis.hash, true, [], @key, 50e8)

  #     list = @wallet.list
  #     list.size.should == 1
  #     list[0][0].should == {addr: @key.addr}
  #     list[0][1].should == 50e8

  #     tx = @wallet.new_tx([[:address, @key2.addr, 10e8]])
  #     tx.in[0].sig_hash.should != nil
  #   end

  # end

  # # TODO
  # describe "Bitcoin::Wallet::Wallet#tx (multisig)" do


  #   before do
  #     txout = txout_mock(5000, nil)
  #     tx = Mock.new
  #     tx.expect(:binary_hash, "foo")
  #     4.times { tx.expect(:out, [txout]) }
  #     tx.expect(:get_block, true)
  #     txout.expect(:get_tx, tx)
  #     2.times { txout.expect(:get_address, @addr) }
  #     4.times { txout.expect(:pk_script, Script.to_address_script(@addr)) }
  #     @storage.expect(:get_txouts_for_address, [txout], [@key.addr])
  #     @storage.expect(:get_txouts_for_address, [txout], [@key2.addr])
  #     @storage.expect(:get_txouts_for_address, [txout], [@key3.addr])
  #     @storage.expect(:class, Bitcoin::Storage::Backends::SequelStore, [])
  #     @keystore = DummyKeyStore.new([@key, @key2, @key3])
  #     selector = Mock.new
  #     selector.expect(:select, [txout], [1000])
  #     @selector.expect(:new, selector, [[txout]])
  #     @wallet = Wallet.new(@storage, @keystore, @selector)
  #     @tx = @wallet.new_tx([[:multisig, 1, @key2.pub, @key3.pub, 1000]])
  #   end

  #   it "should have correct outputs" do
  #     @tx.out.size.should == 2
  #     @tx.out.first.value.should == 1000
  #     s = Script.new(@tx.out.first.pk_script)
  #     s.get_addresses.should == [@addr2, @addr3]
  #   end

  # end

end
