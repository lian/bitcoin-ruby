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

end

