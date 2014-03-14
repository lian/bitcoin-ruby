# encoding: ascii-8bit

require_relative '../spec_helper.rb'

include Bitcoin::Protocol

describe 'TxIn' do

  describe '#initialize without specifying script_sig_length and script_sig' do
    it 'still creates a serializable TxIn' do
      prev_tx = Tx.new fixtures_file('rawtx-01.bin')
      tx_in = TxIn.new prev_tx.binary_hash, 0
      lambda { tx_in.to_payload }.should.not.raise
    end
  end

  it "should compare txins" do
    i1 = Tx.new(fixtures_file('rawtx-01.bin')).in[0]
    i1_1 = TxIn.new(i1.prev_out, i1.prev_out_index, i1.script_sig_length, i1.script_sig)
    i2 = Tx.new(fixtures_file('rawtx-02.bin')).in[0]

    (i1 == i1).should == true
    (i1 == i1_1).should == true
    (i1 == i2).should == false
    (i1 == nil).should == false
  end
  
  it "should be final only when sequence == 0xffffffff" do
    txin = TxIn.new
    txin.is_final?.should == true
    txin.sequence.should == TxIn::DEFAULT_SEQUENCE
    
    txin.sequence = "\x01\x00\x00\x00"
    txin.is_final?.should == false
    
    txin.sequence = "\x00\x00\x00\x00"
    txin.is_final?.should == false

    txin.sequence = "\xff\xff\xff\xff"
    txin.is_final?.should == true
  end
  

end

