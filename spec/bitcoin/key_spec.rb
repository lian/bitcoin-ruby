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

end

describe "Bitcoin::KeyGenerator" do

  # it "should use random data if no seed given" do
  #   g = Bitcoin::KeyGenerator.new
  #   g.seed.size.should == 64
  # end

  it "should find the nonce if not given" do
    Bitcoin::KeyGenerator.new("etd").nonce.should == 622
    # Bitcoin::KeyGenerator.new("foo").nonce.should == 2116
    # Bitcoin::KeyGenerator.new("bar").nonce.should == 72353
    # Bitcoin::KeyGenerator.new("baz").nonce.should == 385471
    # Bitcoin::KeyGenerator.new("qux").nonce.should == 29559
  end

  it "should find keys" do
    g = Bitcoin::KeyGenerator.new("foo")
    [
     "\x05\"\x12\x11\xA9\xC3\xED\xB9\xBD\xF0\xC1 w\r\xC5\x8D#Y\t\x8Co\x16\xF6\xE2i\xF7\"\xF7\xDD\xA2|\xC9",
     "\x7F'\xBB\f\xA0.U\x8CKKN&t\x17Cz\xDA\xC0\x14\x03\xE0\xD0\xBB\x9B\ay}\x1D\xBB\x1A\xDF\xD1",
     "\xDAS\xDE\xC9\x91d\x06\xBB\x9AA+\xFD\xC8\x1A8\x92\xBB\xCB\x15`\xAB9L\xB9\xB9\xFC>\xE2\xA4\x11\x01\xFF",
     "}c\xC8\x8D\n\xB0#\xDE4A\xFF&\x85H\xDC_Yb>\xFE8\xFD\xF4\x81\xBD\xEB\xC8\xBBPG\xC2\xF2",
     "\xF5\x82\x83\x8D\xCB\xA2\xA1s\x93\aD\x84\x05\x90P(\xE30\xE2\xC9\xDE*\x8E\xC2N\xED\x16H\xB8\xBD\xDA\xA4",
     "\xF48\xA3\xFF\x8E\xA0\xEED\"\xF8:Eo\xA6\xCA\xDF\x853\x81\xC0\x9AG4\xAE_\xBB\xAEalSZ\x91",
     ":tB\xAAT\xF6j\xE1\xC8\xA0\xD3R4e\x87I\"i\xB7\xC8\x00\xA01\x9C\x97\x89\xA8\x16@T\xC5\x9E",
     "R=vF\x7F\x9C\t\e\fr@\xDC\xC5\ty|\x89\x00\xD40;r\fj\xFD\xC4\xF2\x18\xB4:\x13)",
     "\xA1\e\xFA@\xA0\xE9 \xBFD\x9E\xF0\xEC\x1D\x17\x05\x13\xC7\xC8-\xAA\xFD\x8CJ\xE3\xC0\xE3!\xDD\xF5\xFA\\\xCE",
     "\x86\xA6\f\xBB\xAD*\xAD\xFB\xA9\x10\xF6=\xC5X\xDD\x87wua)x\x10gK\xEC\x02\x0F\x0F\x9F\x86\xF60",
     "\xCD\x1F\xCA~\xC2\xBD\xDD\xDCW\xFAij\xEF\xA19\e\xF5\xEE\xEA3+y\xA1\xF2\x9C\xFC\xCF\xCC\xF0\x82\xA4t",
    ].each_with_index do |key, i|
      g.get_key(i).priv.should == key.unpack("H*")[0]
    end

  end

end
