require_relative '../spec_helper'

include Bitcoin
include Bitcoin::Wallet

describe "Bitcoin::Wallet::SimpleKeyStore" do

  before do
    @filename = File.join(File.dirname(__FILE__), '../fixtures/wallet/test1.json')
    @ks = SimpleKeyStore.new(file: @filename)
  end

  it "should create new store" do
    filename = @filename.sub('test1', 'test2')
    ks = SimpleKeyStore.new(file: filename)
    ks.keys.size.should == 1
    File.delete(filename) rescue nil
  end

  it "should load store" do
    @ks.keys.size.should == 1
  end

  it "should save store" do
    filename = @filename.sub('test1', 'test2')
    ks = SimpleKeyStore.new(file: filename)
    ks.save_keys
    ks2 = SimpleKeyStore.new(file: filename)
    ks2.keys.should == ks.keys
    File.delete(filename) rescue nil
  end

  it "should create new key" do
    key = @ks.new_key
    @ks.keys.last.should == key
  end

  it "should delete key" do
    @ks.delete(@ks.keys.last.addr)
    @ks.keys.size.should == 1
  end

  it "should get key" do
    @ks.key('1BCRMoSpZ26Wt9igQh97ZN1mUGXF2bj7ty').priv.should ==
      '9d87f35fa07971c0ad29ada861ecf2edb8fd06540c97562d84817ea7b3416e84'
  end

  it "should get keys" do
    @ks.keys.map(&:priv).should ==
      ['9d87f35fa07971c0ad29ada861ecf2edb8fd06540c97562d84817ea7b3416e84']
  end

  it "should export key" do
    @ks.export('1BCRMoSpZ26Wt9igQh97ZN1mUGXF2bj7ty').should ==
      '5K1fW1R2jqLN6GGSgvPp2zc8LSsFBpZagTwriYczvjdhVTrotp2'
  end

  it "should import key" do
    @ks.import('5JUw75N58166KuA4Pb9s2iJARfu6MC7VaQtFZn523VMuXVYUVSm')
    @ks.key('1JovdwZKSby5q3kHLMCX3cCais5YBKVA9x').priv.should ==
      '57c0aea88323c96a75e461499571482ee90d98670a023213f8000047dfa3755c'
    @ks.delete('1JovdwZKSby5q3kHLMCX3cCais5YBKVA9x')
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
    @ks.key('1KDUUSjPJkKwVEJsfpxEzBAf7iEbmqUwUu').priv.should ==
      '7f27bb0ca02e558c4b4b4e267417437adac01403e0d0bb9b07797d1dbb1adfd1'
  end

  it "should get keys" do
    @ks.keys.map(&:priv).should ==
      ['7f27bb0ca02e558c4b4b4e267417437adac01403e0d0bb9b07797d1dbb1adfd1']
  end

  it "should export key" do
    @ks.export('1KDUUSjPJkKwVEJsfpxEzBAf7iEbmqUwUu').should ==
      '5JnHbCHicVj2Wgd2KgNPU7dQ6te55GzHjc4PH9cQDFUjeepYSHX'
  end

end
