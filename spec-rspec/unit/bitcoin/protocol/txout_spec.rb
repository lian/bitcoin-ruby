# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Protocol::TxOut do
  it '#initialize without specifying script_sig_length' do
    key = Bitcoin::Key.generate
    tx_out = Bitcoin::Protocol::TxOut.new(
      12_345,
      Bitcoin::Script.from_string(
        "OP_DUP OP_HASH160 #{key.hash160} OP_EQUALVERIFY OP_CHECKSIG"
      ).to_payload
    )

    tx_out.to_payload
  end

  it 'should compare txouts' do
    o1 = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-01.bin')).out[0]
    o11 = Bitcoin::Protocol::TxOut.new(o1.value, o1.pk_script)
    o2 = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-02.bin')).out[0]

    expect(o1).to eq(o1)
    expect(o1).to eq(o11)
    expect(o1).not_to eq(o2)
    expect(o1).not_to be_nil
  end

  it 'should update parsed script cache on script change' do
    out = Bitcoin::Protocol::TxOut.new(123, 'abc')
    parsed = out.parsed_script
    out.pk_script = 'def'
    expect(out.parsed_script).not_to eq(parsed)
  end
end
