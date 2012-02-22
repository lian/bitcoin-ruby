require_relative '../spec_helper'
require 'json'
include Bitcoin
include Bitcoin::Wallet

describe "Bitcoin::Wallet::SimpleKeyStore" do

  @test1 = [{:label => "test1", :addr => "174xCfTggAovtDezgswTgfUeCp1hWJ1i7F", :pub => "040795786162a1a2fb5bb82310fc1b0da3ced5ed8fc3495bbf848b0156eca465688b0cf08d5389c026556213b7e5ccf471d259575e1756e3352ded2a3eec6a59c8", :priv => "c04ea613926036d2782d43eca89512724c9f33f3e8484adb8b952a3837564bcb"}]

  before do
    spec_dir = File.join(File.dirname(__FILE__), '../fixtures/wallet')
    FileUtils.mkdir_p(spec_dir)
    @filename = File.join(spec_dir, 'test1.json')
    File.open(@filename, 'w') {|f| f.write(@test1.to_json) }
    @ks = SimpleKeyStore.new(file: @filename)
  end

  after do
    File.delete(@filename) rescue nil
  end

  it "should create new store" do
    filename = @filename.sub('test1', 'test2')
    File.open(filename, 'w') {|f| f.write(@test1.to_json) }
    ks = SimpleKeyStore.new(file: filename)
    ks.keys.size.should == 1
    File.delete(filename) rescue nil
  end

  it "should load store" do
    @ks.keys.size.should == 1
  end

  it "should save store" do
    filename = @filename.sub('test1', 'test2')
    File.open(filename, 'w') {|f| f.write(@test1.to_json) }
    ks = SimpleKeyStore.new(file: filename)
    ks.save_keys
    ks2 = SimpleKeyStore.new(file: filename)
    ks2.keys.should == ks.keys
    File.delete(filename) rescue nil
  end

  it "should create new key" do
    key = @ks.new_key
    @ks.keys.last.should == {:label => nil, :addr => key.addr, :key => key}
  end

  it "should delete key" do
    @ks.delete(@ks.keys.last[:addr])
    @ks.keys.size.should == 0
  end

  it "should get key" do
    k1 = @ks.key('174xCfTggAovtDezgswTgfUeCp1hWJ1i7F')[:key]
    k2 = @ks.key('test1')[:key]
    k3 = @ks.key(k2.pub)[:key]
    [k1,k2,k3].each{|k| k.priv.should ==
      'c04ea613926036d2782d43eca89512724c9f33f3e8484adb8b952a3837564bcb'}
  end

  it "should get keys" do
    @ks.keys.map{|k|k[:key].priv}.should ==
      ['c04ea613926036d2782d43eca89512724c9f33f3e8484adb8b952a3837564bcb']
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
