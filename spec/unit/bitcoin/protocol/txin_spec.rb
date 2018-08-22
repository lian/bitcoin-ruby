# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe 'Bitcoin::Protocol::TxIn' do
  describe '#initialize without specifying script_sig_length and script_sig' do
    it 'still creates a serializable TxIn' do
      prev_tx = Bitcoin::Protocol::Tx.new(
        fixtures_file('rawtx-01.bin')
      )
      tx_in = Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0)
      tx_in.to_payload
    end
  end

  it 'should compare txins' do
    i1 = Bitcoin::Protocol::Tx.new(
      fixtures_file('rawtx-01.bin')
    ).in[0]
    i11 = Bitcoin::Protocol::TxIn.new(
      i1.prev_out, i1.prev_out_index, i1.script_sig_length, i1.script_sig
    )
    i2 = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-02.bin')).in[0]

    expect(i1).to eq(i1)
    expect(i1).to eq(i11)
    expect(i1).not_to be_nil
    expect(i1).not_to eq(i2)
  end

  it 'should be final only when sequence == 0xffffffff' do
    txin = Bitcoin::Protocol::TxIn.new
    expect(txin.final?).to be true
    expect(txin.sequence)
      .to eq(Bitcoin::Protocol::TxIn::DEFAULT_SEQUENCE)

    txin.sequence = "\x01\x00\x00\x00"
    expect(txin.final?).to be false

    txin.sequence = "\x00\x00\x00\x00"
    expect(txin.final?).to be false

    txin.sequence = "\xff\xff\xff\xff"
    expect(txin.final?).to be true
  end
end
