# encoding: ascii-8bit

require_relative '../spec_helper'


include Bitcoin::Wallet
describe "Bitcoin::KeyGenerator" do

  @target = ("\x00\xff" + "\x00"*30).unpack("H*")[0].to_i(16)

  before do
    Bitcoin.network = :bitcoin
  end

  it "should use random data if no seed given" do
    g = KeyGenerator.new(nil, nil, @target)
    g.seed.size.should == 64
  end

  it "should find the nonce if not given" do
    KeyGenerator.new("etd").nonce.should == 622
    KeyGenerator.new("foo").nonce.should == 2116
    # KeyGenerator.new("bar").nonce.should == 72353
    # KeyGenerator.new("baz").nonce.should == 385471
    # KeyGenerator.new("qux").nonce.should == 29559
  end

  it "should use given nonce" do
    g = KeyGenerator.new("foo", 2116)
    g.nonce.should == 2116
    key = g.get_key(0)
    key.addr.should == '1JvRdnShvscPtoP44VxPk5VaFBAo7ozRPb'
    key.instance_eval { @pubkey_compressed = false }
    key.addr.should == '1GjyUrY3XcR4BvfgL8HqoAJbNDEgxSJdm1'
  end

  it "should check nonce if given" do
    -> { KeyGenerator.new("foo", 42) }.should.raise ArgumentError
  end

  it "should use different target if given" do
    g = KeyGenerator.new("foo", nil, @target)
    g.nonce.should == 127
    g.get_key(0).addr.should == "1KLBACvBnz9BTdBnuJmNuQpKQrsi55sstj"
    g = KeyGenerator.new("bar", nil, @target)
    g.nonce.should == 40
    g.get_key(0).addr.should == "14T4deW5BGVA7wXpR3eoU9U8xprUJepxcy"
  end

  it "should find keys" do
    g = KeyGenerator.new("foo")
    [
     "05221211a9c3edb9bdf0c120770dc58d2359098c6f16f6e269f722f7dda27cc9",
     "7f27bb0ca02e558c4b4b4e267417437adac01403e0d0bb9b07797d1dbb1adfd1",
     "da53dec9916406bb9a412bfdc81a3892bbcb1560ab394cb9b9fc3ee2a41101ff",
     "7d63c88d0ab023de3441ff268548dc5f59623efe38fdf481bdebc8bb5047c2f2",
     "f582838dcba2a1739307448405905028e330e2c9de2a8ec24eed1648b8bddaa4",
     "f438a3ff8ea0ee4422f83a456fa6cadf853381c09a4734ae5fbbae616c535a91",
     "3a7442aa54f66ae1c8a0d352346587492269b7c800a0319c9789a8164054c59e",
     "523d76467f9c091b0c7240dcc509797c8900d4303b720c6afdc4f218b43a1329",
     "a11bfa40a0e920bf449ef0ec1d170513c7c82daafd8c4ae3c0e321ddf5fa5cce",
     "86a60cbbad2aadfba910f63dc558dd87777561297810674bec020f0f9f86f630",
     "cd1fca7ec2bddddc57fa696aefa1391bf5eeea332b79a1f29cfccfccf082a474",
    ].map{|h| [h].pack("H*")}.each_with_index do |key, i|
      g.get_key(i).priv.should == key.unpack("H*")[0]
    end
  end

end
