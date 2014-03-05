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

end

