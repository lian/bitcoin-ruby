require_relative 'spec_helper'

describe "Bitcoin::Key" do

  before do
    Bitcoin.network = :bitcoin
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

begin
  describe "Bitcoin::OpenSSL_EC" do
    Bitcoin::OpenSSL_EC

    it 'resolves public from private key' do
      Bitcoin.network = :testnet
      privkey = ["56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc"].pack("H*")
      pubkey =  ["04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3"].pack("H*")

      Bitcoin::OpenSSL_EC.regenerate_key(privkey).should == [privkey, pubkey].map{|i| i.unpack("H*")[0] }

      [
        ["b51386f8275d49d8d30287d7b1afa805790bdd1fe8b13d22d25928c67ea55d02", "0470305ae5278a22499980286d9c513861d89e7b7317c8b891c554d5c8fdd256b03daa0340be4104f8c84cfa98f0da8f16567fcdd3a00fd993adbbe91695671a56"],
        ["d8ebece51adc5fb99dd6994bcb8fa1221d01576fd76af9134ab36f8d4698b55c", "047503421850d3a6eecb7c9de33b367c4d3f96a34ff257ad0c34e234e29f3672525c6b4353ce6fdc9de3f885fdea798982e2252e610065dbdb62cd8cab1fe45822"],
        ["c95c79fb0cc1fe47b384751df0627be40bbe481ec94eeafeb6dc40e94c40de43", "04b746ca07e718c7ca26d4eeec037492777f48bb5c750e972621698f699f530535c0ffa96dad581102d0471add88e691af85955d1fd42f68506f8092fddfe0c47a"],
        ["5b61f807cc938b0fd3ec8f6006737d0002ceca09f296204138c4459de8a856f6", "0487357bf30c13d47d955666f42f87690cfd18be96cc74cda711da74bf76b08ebc6055aba30680e6288df14bda68c781cbf71eaad096c3639e9724c5e26f3acf54"]
      ].each{|key|
        privkey, pubkey = [ key.first ].pack("H*")
        Bitcoin::OpenSSL_EC.regenerate_key(privkey).should == key
      }

      250.times.map{
        keypair = Bitcoin.generate_key;
        Bitcoin::OpenSSL_EC.regenerate_key(keypair.first) == keypair
      }.all?.should == true
    end

  end
rescue LoadError
end
