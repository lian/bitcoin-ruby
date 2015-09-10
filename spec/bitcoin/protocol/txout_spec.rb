# encoding: ascii-8bit

require_relative '../spec_helper.rb'

include Bitcoin::Protocol

describe 'TxOut' do

  it '#initialize without specifying script_sig_length' do
    key = Bitcoin::Key.generate
    tx_out = TxOut.new(12345, Bitcoin::Script.from_string("OP_DUP OP_HASH160 #{key.hash160} OP_EQUALVERIFY OP_CHECKSIG").to_payload)
    lambda { tx_out.to_payload }.should.not.raise
  end

  it "should compare txouts" do
    o1 = Tx.new(fixtures_file('rawtx-01.bin')).out[0]
    o1_1 = TxOut.new(o1.value, o1.pk_script)
    o2 = Tx.new(fixtures_file('rawtx-02.bin')).out[0]

    (o1 == o1).should == true
    (o1 == o1_1).should == true
    (o1 == o2).should == false
    (o1 == nil).should == false
  end

  describe ".from_hash" do
    before do
      @hash = {
        "spent"    => false,
        "tx_index" => 101431844,
        "type"     => 0,
        "addr"     => "1Az1Sh9Tai6gFfEzFczhHY27WiQ99ZZURtA",
        "value"    => "1234",
        "n"        => 0,
        "script"   => "d6c66cd822a22d7da0ce388589bb161d8667e40e5279f20fd2"
      }
      @script = Bitcoin::Script.binary_from_string(@hash["script"])
    end

    it "creates a new TxOut from the hash" do
      txout = TxOut.from_hash(@hash)
      txout.value.should            == 1234
      txout.pk_script               == @script
      txout.pk_script_length.should == @script.bytesize
    end

  end
end
