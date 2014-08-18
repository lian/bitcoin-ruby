# encoding: ascii-8bit

require_relative '../spec_helper'
require 'json'
require 'fileutils'
include Bitcoin
include Bitcoin::Wallet

describe "Bitcoin::Wallet::SimpleKeyStore" do

  @test1 = [
    {:label => "test1", :addr => "174xCfTggAovtDezgswTgfUeCp1hWJ1i7F", :pub => "040795786162a1a2fb5bb82310fc1b0da3ced5ed8fc3495bbf848b0156eca465688b0cf08d5389c026556213b7e5ccf471d259575e1756e3352ded2a3eec6a59c8", :priv => "c04ea613926036d2782d43eca89512724c9f33f3e8484adb8b952a3837564bcb", :mine => true, :hidden => false},
    # 5J4iJt8Co9uzmAK7SnLLkvP6dY9s6882kiF4ZCJCNBpZf8QHjVf
    {:addr => "135o74rH4r7vxEuDdozehLeTuzBG7ABdCA", :pub => "04608f68aafef3f216dcb0851bbda7834097a43a0b25794611ebea1177d60c52b25d944ee8c1974f4c9de3d2069cb7ebff803b75487f1f725a6c36a68c2a5ec4ad", :priv => "20c1bb60d9242db6240ae125baa0c2eea838e1e33085ff23e36b7dc4e76bb869", :mine => true, :hidden => false},
    # 5JPbwuNwBWDAsKHzSCUWjvZUkwMFooSXEZrDmnQo5wpEGXcfjJY
    {:label => "test3", :addr => "1Esx52p3MXsjkWWvUM8Pwm2NP14Rj5GkDF",
      :mine => false, :hidden => false},
    # 5Hz9HLAm4t8Mgh8i5mGQm7dgqb2R4V88yVUX6RUf2o77uZus7NP
    {:label => "test4", :addr => "1F17yu83Rhtg78f8ZoEseXo6aprC1D9fwi",
      :mine => false, :hidden => true},
    # 5JQnYo4DNdUKKwMiMwQQxova9NExAgPjZybipjx73RxzTTwARch
    {:label => "test5", :addr => "17NgKZgaDphrfvdBxmX1EssLX7Jyq4ZA22",
      :mine => true, :hidden => false},
    # 5KD3KboVn9a31FWZKZ7NxbbvWcbc5f32D3MkU8kfBzFkw7abRZL
    {:addr => "1MnSMHjyVSEJE8eC4GUHtuDbvzHbnDBGP7", :pub => "04d4aa8b12642e533a8c3c63a8d99d03b77e642b23134cc4dde11065845a24bca86dd3fa2d4d8801bbc2c032597f9f780e72940a90081be743c0051f9cd286b935", :mine => false, :hidden => false},
  ]

  before do
    Bitcoin.network = :bitcoin
    file_stub = StringIO.new
    file_stub.write(@test1.to_json); file_stub.rewind
    @ks = SimpleKeyStore.new(file: file_stub)
    @key = Bitcoin::Key.generate
  end

  it "should create new store" do
    file_stub = StringIO.new
    file_stub.write(@test1.to_json); file_stub.rewind
    ks = SimpleKeyStore.new(file: file_stub)
    ks.keys.size.should == 6
  end

  it "should load store" do
    @ks.keys.size.should == 6
  end

  it "should save store" do
    file_stub = StringIO.new
    file_stub.write(@test1.to_json); file_stub.rewind
    ks = SimpleKeyStore.new(file: file_stub)
    ks.save_keys
    ks2 = SimpleKeyStore.new(file: file_stub)
    ks2.keys.should == ks.keys
  end

  it "should create new key" do
    key = @ks.new_key
    @ks.keys.last.should == {:label => nil, :addr => key.addr, :key => key}
  end

  it "should delete key" do
    @ks.delete(@ks.keys.last[:addr])
    @ks.keys.size.should == 5
  end

  it "should get key" do
    k1 = @ks.key('174xCfTggAovtDezgswTgfUeCp1hWJ1i7F')[:key]
    k2 = @ks.key('test1')[:key]
    k3 = @ks.key(k2.pub)[:key]
    [k1,k2,k3].each{|k| k.priv.should ==
      'c04ea613926036d2782d43eca89512724c9f33f3e8484adb8b952a3837564bcb'}
  end

  it "should get keys" do
    @ks.key('test1')[:key].priv.should ==
      'c04ea613926036d2782d43eca89512724c9f33f3e8484adb8b952a3837564bcb'
  end

  it "should export key" do
    k1 = @ks.export('174xCfTggAovtDezgswTgfUeCp1hWJ1i7F')
    k2 = @ks.export('test1')
    k3 = @ks.export(@ks.key('test1')[:key].pub)
    [k1,k2,k3].uniq.should == ['5KGyp1k36dqprA9zBuzEJzf327vw4bTkJARcW13zAKBhAfVmeT3']
  end

  it "should import key" do
    @ks.import('5JUw75N58166KuA4Pb9s2iJARfu6MC7VaQtFZn523VMuXVYUVSm')
    @ks.key('1JovdwZKSby5q3kHLMCX3cCais5YBKVA9x')[:key].priv.should ==
      '57c0aea88323c96a75e461499571482ee90d98670a023213f8000047dfa3755c'
    @ks.delete('1JovdwZKSby5q3kHLMCX3cCais5YBKVA9x')
    @ks.import('5JUw75N58166KuA4Pb9s2iJARfu6MC7VaQtFZn523VMuXVYUVSm', "test2")
    @ks.key('test2')[:key].priv.should ==
      '57c0aea88323c96a75e461499571482ee90d98670a023213f8000047dfa3755c'
  end

  it "should not allow the same label twice" do
    -> { @ks.new_key("test1") }.should.raise ArgumentError
    -> { @ks.add_key({:label => "test1", :addr => "12345"}) }.should.raise ArgumentError
    -> { @ks.import("foobar", "test1") }.should.raise ArgumentError
  end

  it "should not allow invalid addrs" do
    -> { @ks.add_key({:addr => "foobar"}) }.should.raise ArgumentError
  end

  it "should store only address" do
    k = {:label => 'test6', :addr => @key.addr}
    @ks.add_key(k)
    @ks.keys.size.should == 7
    @ks.key('test6').should == k
    @ks.key(@key.addr).should == k
  end

  it "should store only pubkey and addr" do
    k = {:label => 'test6', :addr => @key.addr, :pub => @key.pub}
    @ks.add_key(k)
    @ks.keys.size.should == 7
    @ks.key('test6').should == k
    @ks.key(@key.addr).should == k
  end

  it "should store flags" do
    @ks.key('test1')[:mine].should == true
    @ks.key('test1')[:hidden].should == false
    @ks.flag_key 'test1', :hidden, true
    @ks.key('test1')[:hidden].should == true
  end

  it "should list only keys which have a label" do
    @ks.keys(:label).size.should == 4
  end

  it "should list only keys which have a pubkey" do
    @ks.keys(:pub).size.should == 3
  end

  it "should list only keys which have a privkey" do
    @ks.keys(:priv).size.should == 2
  end

  it "should list only hidden keys" do
    @ks.keys(:hidden).size.should == 1
  end

  it "should list only keys which are 'mine'" do
    @ks.keys(:mine).size.should == 3
  end

end


describe "Bitcoin::Wallet::DeterministicKeyStore" do

  before do
    @ks = DeterministicKeyStore.new(:seed => "foo", :keys => 1, :nonce => 2116)
  end

  it "should create new store" do
    ks = DeterministicKeyStore.new(:seed => "etd", :keys => 3)
    ks.keys.size.should == 3
    ks.generator.nonce.should == 622
  end

  it "should load store" do
    @ks.keys.map(&:priv).should ==
      ['7f27bb0ca02e558c4b4b4e267417437adac01403e0d0bb9b07797d1dbb1adfd1']
  end

  it "should create new key" do
    key = @ks.new_key
    key.priv.should == 'da53dec9916406bb9a412bfdc81a3892bbcb1560ab394cb9b9fc3ee2a41101ff'
    @ks.keys.last.should == key
  end

  it "should get key" do
    @ks.key('1GKjKQemNRhxL1ChTRFJNLZCXeCDxut2d7').priv.should ==
      '7f27bb0ca02e558c4b4b4e267417437adac01403e0d0bb9b07797d1dbb1adfd1'
  end

  it "should get keys" do
    @ks.keys.map(&:priv).should ==
      ['7f27bb0ca02e558c4b4b4e267417437adac01403e0d0bb9b07797d1dbb1adfd1']
  end

  it "should export key" do
    @ks.export('1GKjKQemNRhxL1ChTRFJNLZCXeCDxut2d7').should ==
      'L1UtDvpnffnVg1szqSmQAgFexzvcysZrs3jwLH1FT4uREpZqcXaR'
  end

end
