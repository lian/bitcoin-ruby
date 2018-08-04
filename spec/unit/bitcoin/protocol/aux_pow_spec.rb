# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Protocol::AuxPow do
  before { Bitcoin.network = :namecoin }
  let(:data) { fixtures_file('rawblock-auxpow.bin') }
  let(:blk) { Bitcoin::Protocol::Block.new(data) }
  let(:aux_pow) { blk.aux_pow }

  it 'should parse AuxPow' do
    expect(aux_pow).not_to be_nil
    expect(aux_pow.block_hash.hth)
      .to eq('b42124fd99e67ddabe52ebbfcb30a82b8c74268a320b3c5e2311000000000000')
    expect(aux_pow.coinbase_branch)
      .to eq(
        %w[
          c22f79ba86968a5285225008b2740f074f44f44ef27b8efb61ecff09e9eb4f6d
          99696473beb0caa79d4209dbaa6e18fdc23ebdc67210f86fec0c4559847252d0
          20cbcff309ec8c267892a476c1b22d23d9e5d7a6fdfd025658de6c2ae4e7c564
          e4317593d6ad8d735ded56c336376b7409207c3ea6b92b2451f79eced606944e
        ]
      )
    expect(aux_pow.coinbase_index).to eq(0)
    expect(aux_pow.chain_branch).to be_empty
    expect(aux_pow.chain_index).to eq(0)
    expect(aux_pow.parent_block.hash).to eq(
      '00000000000011235e3c0b328a26748c2ba830cbbfeb52beda7de699fd2421b4'
    )
  end

  it '#to_payload' do
    expect(blk.to_payload).to eq(data)
    expect(Bitcoin::Protocol::Block.new(blk.to_payload).to_payload).to eq(data)
  end

  it '#to_hash' do
    expect(Bitcoin::Protocol::Block.from_hash(blk.to_hash).to_payload).to eq(data)
  end

  it '#to_json' do
    expect(Bitcoin::Protocol::Block.from_json(blk.to_json).to_payload).to eq(data)
  end
end
