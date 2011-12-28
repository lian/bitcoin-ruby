require_relative 'spec_helper'

describe "Bitcoin::Key" do

  before do
    @key_data = {
      :priv => "2ebd3738f59ae4fd408d717bf325b4cb979a409b0153f6d3b4b91cdfe046fb1e",
      :pub => "045fcb2fb2802b024f371cc22bc392268cc579e47e7936e0d1f05064e6e1103b8a81954eb6d3d33b8b6e73e9269013e843e83919f7ce4039bb046517a0cad5a3b1" }
    @key = Bitcoin::Key.new(@key_data[:priv], @key_data[:pub])
  end

  it "should generate a key" do
    k = Bitcoin::Key.generate
    k.priv.size.should == 64
    k.pub.size.should == 130
    #p k.priv, k.pub
  end

  it "should create empty key" do
    k = Bitcoin::Key.new
    k.priv.should == nil
    k.pub.should == nil
  end

  it "should create key from priv + pub" do
    k = Bitcoin::Key.new(@key_data[:priv], @key_data[:pub])
    k.priv.should == @key_data[:priv]
    k.pub.should == @key_data[:pub]
  end

  it "should create key from only priv" do
    k = Bitcoin::Key.new(@key_data[:priv])
    k.priv.should == @key_data[:priv]
    k.pub.should == @key_data[:pub]
  end

  it "should create key from only pub" do
    k = Bitcoin::Key.new(nil, @key_data[:pub])
    k.pub.should == @key_data[:pub]
  end

  it "should set public key" do
    k = Bitcoin::Key.new
    k.pub = @key_data[:pub]
    k.pub.should == @key_data[:pub]
  end

  it "should set private key" do
    k = Bitcoin::Key.new
    k.priv = @key_data[:priv]
    k.priv.should == @key_data[:priv]
    k.pub.should == @key_data[:pub]
  end

  it "should get addr" do
    @key.addr.should == "1JbYZRKyysprVjSSBobs8LX6QVjzsscQNU"
  end

  it "should sign data" do
    @key.sign("foobar").size.should >= 69
  end

  it "should verify signature" do
    sig = @key.sign("foobar")
    key2 = Bitcoin::Key.new(nil, @key.pub)
    @key.verify("foobar", sig).should == true
  end

  it "should export private key in base58 format" do
    Bitcoin.network = :bitcoin
    str = Bitcoin::Key.new("e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262").to_base58
    str.should == "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
    Bitcoin.network = :testnet
    str = Bitcoin::Key.new("d21fa2c7ad710ffcd9bcc22a9f96357bda1a2521ca7181dd610140ecea2cecd8").to_base58
    str.should == "93BTVFoqffueSaC5fqjLjLyn29S41JzvAZm2hC35SYMoYDXT1bY"
    Bitcoin.network = :bitcoin
  end

  it "should import private key in base58 format" do
    Bitcoin.network = :bitcoin
    key = Bitcoin::Key.from_base58("5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF")
    key.priv.should == "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
    key.addr.should == "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj"
    Bitcoin.network = :testnet
    key = Bitcoin::Key.from_base58("93BTVFoqffueSaC5fqjLjLyn29S41JzvAZm2hC35SYMoYDXT1bY")
    key.priv.should == "d21fa2c7ad710ffcd9bcc22a9f96357bda1a2521ca7181dd610140ecea2cecd8"
    key.addr.should == "n3eH91H14mSnGx4Va2ngtLFCeLPRyYymRg"
    Bitcoin.network = :bitcoin
  end

end

describe "Bitcoin::KeyGenerator" do

  @target = ("\x00\xff" + "\x00"*30).unpack("H*")[0].to_i(16)

  it "should use random data if no seed given" do
    g = Bitcoin::KeyGenerator.new(nil, nil, @target)
    g.seed.size.should == 64
  end

  it "should find the nonce if not given" do
    Bitcoin::KeyGenerator.new("etd").nonce.should == 622
    Bitcoin::KeyGenerator.new("foo").nonce.should == 2116
    # Bitcoin::KeyGenerator.new("bar").nonce.should == 72353
    # Bitcoin::KeyGenerator.new("baz").nonce.should == 385471
    # Bitcoin::KeyGenerator.new("qux").nonce.should == 29559
  end

  it "should use given nonce" do
    g = Bitcoin::KeyGenerator.new("foo", 2116)
    g.nonce.should == 2116
    g.get_key(0).addr.should == '1GjyUrY3XcR4BvfgL8HqoAJbNDEgxSJdm1'
  end

  it "should check nonce if given" do
    -> { Bitcoin::KeyGenerator.new("foo", 42) }.should.raise ArgumentError
  end

  it "should use different target if given" do
    g = Bitcoin::KeyGenerator.new("foo", nil, @target)
    g.nonce.should == 127
    g.get_key(0).addr.should == "13E68pPJyGycgQ4ZmV45xV9r9XEeyWqZdp"
    g = Bitcoin::KeyGenerator.new("bar", nil, @target)
    g.nonce.should == 40
    g.get_key(0).addr.should == "12iQpWRRQBmWcHYkTZkpDFrykzc9xn5kAU"
  end

  it "should find keys" do
    g = Bitcoin::KeyGenerator.new("foo")
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
