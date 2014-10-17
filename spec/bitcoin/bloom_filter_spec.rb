require_relative 'spec_helper.rb'
include Bitcoin

describe BloomFilter do

  before { @filter = BloomFilter.new(10, 0.1, 0, :update_all) }

  it "should do rotl32" do
    {
      [0, 0] => 0,
      [0, 1] => 0,
      [0, 2] => 0,
      [0, 3] => 0,
      [1, 0] => 1,
      [2, 0] => 2,
      [3, 0] => 3,
      [1, 2] => 4,
      [2, 2] => 8,
      [3, 2] => 12,
      [1, 1] => 2,
      [2, 1] => 4,
      [3, 1] => 6,
      [2, 3] => 16,
    }.each {|i, o| @filter.rotl32(*i).should == o }
  end

  it "should do murmurhash3" do
    [
     [0x00000000, 0x00000000, ""],
     [0x6a396f08, 0xFBA4C795, ""],
     [0x81f16f39, 0xffffffff, ""],

      [0x514e28b7, 0x00000000, "00"],
      [0xea3f0b17, 0xFBA4C795, "00"],
      [0xfd6cf10d, 0x00000000, "ff"],

      [0x16c6b7ab, 0x00000000, "0011"],
      [0x8eb51c3d, 0x00000000, "001122"],
      [0xb4471bf8, 0x00000000, "00112233"],
      [0xe2301fa8, 0x00000000, "0011223344"],
      [0xfc2e4a15, 0x00000000, "001122334455"],
      [0xb074502c, 0x00000000, "00112233445566"],
      [0x8034d2a0, 0x00000000, "0011223344556677"],
      [0xb4698def, 0x00000000, "001122334455667788"],
    ].each {|e, s, d| @filter.murmurhash3(s, d.htb).should == e }
  end

  def t data
    @filter.insert(data.htb)
    @filter.contains(data.htb).should == true
  end

  def f data
    @filter.contains(data.htb).should == false
  end

  it "should create filter" do
    @filter.size.should == 10
    @filter.fp_rate.should == 0.1
    @filter.tweak.should == 0
    @filter.hash_funcs.should == 2

    @filter = BloomFilter.new(10, 1.0, 0)
    @filter.contains("foo").should == true
  end

  it "should de/serialize filter" do
    data = "050000a00000020000000000000001"
    @filter.insert("foobar")
    @filter.serialize.should == data

    filter = BloomFilter.new(10, 0.1, 0, :update_all)
    filter.deserialize(data)

    [:size, :fp_rate, :tweak, :flags, :hash_funcs, :data].each do |m|
      @filter.send(m).should == filter.send(m)
    end

    filter.contains("foobar").should == true

    @filter = BloomFilter.new(10000, 0.1, 0)
    @filter.insert("foobar")

    filter = BloomFilter.new(10000, 0.1, 0)
    filter.deserialize(@filter.serialize)

    [:size, :fp_rate, :tweak, :flags, :hash_funcs, :data].each do |m|
      @filter.send(m).should == filter.send(m)
    end

    filter.contains("foobar").should == true
  end

  it "should create, insert and serialize" do
    @filter = BloomFilter.new(3, 0.01, 0, :update_all)
    t("99108ad8ed9bb6274d3980bab5a85c048f0950c8")
    f("19108ad8ed9bb6274d3980bab5a85c048f0950c8")
    t("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")
    t("b9300670b4c5366e95b2699e8b18bc75e5f729c5")
    @filter.serialize.should == "03614e9b050000000000000001"
  end

  it "should create, insert and serialize with tweak" do
    # Same test as before, but we add a tweak of 100
    @filter = BloomFilter.new(3, 0.01, 2147483649, :update_all)
    t("99108ad8ed9bb6274d3980bab5a85c048f0950c8")
    f("19108ad8ed9bb6274d3980bab5a85c048f0950c8")
    t("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")
    t("b9300670b4c5366e95b2699e8b18bc75e5f729c5")
    @filter.serialize.should == "03ce4299050000000100008001"
  end

  # TODO

  # def test_bloom_create_insert_key(self):
  #     filter = CBloomFilter(2, 0.001, 0, CBloomFilter.UPDATE_ALL)

  #     pubkey = unhexlify(b'045B81F0017E2091E2EDCD5EECF10D5BDD120A5514CB3EE65B8447EC18BFC4575C6D5BF415E54E03B1067934A0F0BA76B01C6B9AB227142EE1D543764B69D901E0')
  #     pubkeyhash = ser_uint160(Hash160(pubkey))

  #     filter.insert(pubkey)
  #     filter.insert(pubkeyhash)

  #     self.assertEqual(filter.serialize(), unhexlify(b'038fc16b080000000000000001'))

end
