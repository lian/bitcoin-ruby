# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Dogecoin do
  it 'validate dogecoin-address' do
    Bitcoin.network = :dogecoin_testnet

    # Testnet address
    expect(Bitcoin.valid_address?('nUtMFED5VRg5xuj9QCrNFt9mVPFDXo7TTE'))
      .to be true
    # Livenet address
    expect(Bitcoin.valid_address?('DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4'))
      .to be false
    # Broken address
    expect(Bitcoin.valid_address?('DRjyUS2uuieEPkhZNdQz8hE5YycxVEqSXA'))
      .to be false

    Bitcoin.network = :dogecoin

    # Testnet address
    expect(Bitcoin.valid_address?('nUtMFED5VRg5xuj9QCrNFt9mVPFDXo7TTE'))
      .to be false
    # Livenet address
    expect(Bitcoin.valid_address?('DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4'))
      .to be true
    # Broken address
    expect(Bitcoin.valid_address?('DRjyUS2uuieEPkhZNdQz8hE5YycxVEqSXA'))
      .to be false
  end

  it 'should calculate retarget difficulty' do
    Bitcoin.network = :dogecoin

    prev_height = 239
    prev_block_time = 1_386_475_638 # Block 239
    prev_block_bits = 0x1e0ffff0
    last_retarget_time = 1_386_474_927 # Block 1
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1e00ffff.to_s(16))

    prev_height = 479
    prev_block_time = 1_386_475_840
    prev_block_bits = 0x1e0fffff
    last_retarget_time = 1_386_475_638 # Block 239
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1e00ffff.to_s(16))

    prev_height = 9_599
    prev_block_time = 1_386_954_113
    prev_block_bits = 0x1c1a1206
    last_retarget_time = 1_386_942_008 # Block 9359
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1c15ea59.to_s(16))

    # First hard-fork at 145,000, which applies to block 145,001 onwards
    prev_height = 145_000
    prev_block_time = 1_395_094_679
    prev_block_bits = 0x1b499dfd
    last_retarget_time = 1_395_094_427
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1b671062.to_s(16))

    # Test case for correct rounding of modulated time - by default C++ and Ruby
    # do not necessarily round identically
    prev_height = 145_001
    prev_block_time = 1_395_094_727
    prev_block_bits = 0x1b671062
    last_retarget_time = 1_395_094_679
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1b6558a4.to_s(16))

    # Test the second hard-fork at 371,337 as well
    prev_height = 371_336
    prev_block_time = 1_410_464_569
    prev_block_bits = 0x1b2fdf75
    last_retarget_time = 1_410_464_445
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1b364184.to_s(16))

    prev_height = 408_596
    prev_block_time = 1_412_800_112
    prev_block_bits = 0x1b033d8b
    last_retarget_time = 1_412_799_989 # Block 408,595
    new_difficulty = Bitcoin.block_new_target(
      prev_height, prev_block_time, prev_block_bits, last_retarget_time
    )
    expect(new_difficulty.to_s(16)).to eq(0x1b039e52.to_s(16))
  end

  it 'should calculate reward upper bounds' do
    Bitcoin.network = :dogecoin

    # Note this is the maximum possible, not actual reward
    expect(Bitcoin.block_creation_reward(99_000)).to eq(1_000_000 * Bitcoin::COIN)
    # Hard-forked to remove random rewards
    expect(Bitcoin.block_creation_reward(144_999)).to eq(500_000 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(145_000)).to eq(250_000 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(199_999)).to eq(250_000 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(299_999)).to eq(125_000 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(399_999)).to eq(62_500 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(499_999)).to eq(31_250 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(599_999)).to eq(15_625 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(600_000)).to eq(10_000 * Bitcoin::COIN)
    expect(Bitcoin.block_creation_reward(700_000)).to eq(10_000 * Bitcoin::COIN)
  end

  it 'should calculate merkle root from AuxPoW transaction branch' do
    # Taken directly from Dogecoin block #403,931

    # Branch stored as bytes to reflect how data is stored in AuxPow class
    branch = [
      "\xbe\x07\x90\x78\x86\x93\x99\xfa\xcc\xaa\x76\x4c\x10\xe9\xdf\x6e\x99" \
      "\x81\x70\x17\x59\xad\x18\xe1\x37\x24\xd9\xca\x58\x83\x13\x48",
      "\x5f\x5b\xfb\x2c\x79\x54\x17\x78\x49\x9c\xab\x95\x6a\x10\x38\x87\x14" \
      "\x7f\x2a\xb5\xd4\xa7\x17\xf3\x2f\x9e\xee\xbd\x29\xe1\xf8\x94",
      "\xd8\xc6\xfe\x42\xca\x25\x07\x61\x59\xcd\x12\x1a\x5e\x20\xc4\x8c\x1b" \
      "\xc5\x3a\xb9\x07\x30\x08\x3e\x44\xa3\x34\x56\x6e\xa6\xbb\xcb"
    ]
    mrkl_index = 0
    # Coinbase TX ID
    target = '089b911f5e471c0e1800f3384281ebec5b372fbb6f358790a92747ade271ccdf'
    expect(Bitcoin.mrkl_branch_root(branch.map(&:hth), target, mrkl_index))
      .to eq('f29cd14243ed542d9a0b495efcb9feca1b208bb5b717dc5ac04f068d2fef595a')
  end

  it 'should calculate merkle root from AuxPoW branch' do
    # Taken directly from Dogecoin block #403,931

    # Branch stored as bytes to reflect how data is stored in AuxPow class
    aux_branch = [
      "\x47\xa0\x22\x8b\x06\xc9\x36\x8f\x96\xc5\xf0\x4e\xb1\x09\xf8\x2c\xef" \
      "\x36\xda\xe7\xc1\xbf\x25\x4c\x1a\x3f\x78\x61\x5e\xb0\xbe\x83",
      "\xee\x67\xde\x31\x75\x76\x58\xdd\xd7\x40\x3e\x1a\x35\xd9\xc0\x6a\x5a" \
      "\x13\xe6\x68\x98\x44\x3b\x45\x8c\xd6\xa7\x1b\x66\x27\x41\x6c",
      "\xab\x9e\xf9\xbd\xa0\x2c\xad\x27\x90\xef\x9b\xb7\xc9\xa0\x7f\xe1\x79" \
      "\x1a\x9d\x5a\xe0\x43\x09\xc0\xe9\x06\x48\x19\x19\x4c\x28\x31",
      "\xff\x51\x61\x01\x80\xf6\x4d\x33\xa8\xc1\xba\x1d\xd9\xa9\xd0\x40\x48" \
      "\x88\xc9\x6e\xaf\xd1\x57\x03\x64\x35\x8b\xbe\x99\x8f\x2d\xfe",
      "\x9e\xe4\x18\x36\x7c\x3b\xce\x06\x5e\x7c\x01\x61\x29\x6e\xaa\x0d\x54" \
      "\x96\xf9\x0f\x8b\x7b\x24\xeb\xf7\x2c\xc4\xba\xa5\x60\x9a\x1f",
      "\x0b\x35\xf3\x73\x10\xe1\xde\x3f\xa4\xe1\x37\x7c\x02\x12\x62\x20\xe1" \
      "\x64\xfa\x59\xec\xfe\xdc\xf4\x71\x4e\x61\xad\x74\xcc\x4b\x08"
    ]
    aux_mrkl_index = 56
    # Block hash
    target = '0c836b86991631d34a8a68054e2f62db919b39d1ee43c27ab3344d6aa82fa609'
    # Merkle root in coinbase script
    expect(Bitcoin.mrkl_branch_root(aux_branch.map(&:hth), target, aux_mrkl_index))
      .to eq('ce3040fdb7e37484f6a1ca4f8f5da81e6b7e404ec91102315a233e03a0c39c95')
  end

  it 'parse AuxPoW' do
    Bitcoin.network = :dogecoin

    block_hash = '60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053'
    data = fixtures_file("dogecoin-block-#{block_hash}.bin")
    block = Bitcoin::Protocol::Block.new(data)
    aux_pow = block.aux_pow
    expect(aux_pow).not_to be_nil
    expect(aux_pow.coinbase_index).to eq(0)

    parent_block_merkle_root = Bitcoin.mrkl_branch_root(
      aux_pow.coinbase_branch, aux_pow.coinbase_tx.hash, aux_pow.coinbase_index
    )
    expect(parent_block_merkle_root)
      .to eq(aux_pow.parent_block.mrkl_root.reverse.unpack('H*')[0])

    # Find the merged mining header in the coinbase input script
    merged_mining_header = "\xfa\xbemm"
    script = aux_pow.coinbase_tx.in[0].script
    header_idx = script.index(merged_mining_header)

    expect(header_idx).to eq(4)
    chain_merkle_root = Bitcoin.mrkl_branch_root(
      aux_pow.chain_branch, block_hash, aux_pow.chain_index
    )

    # Drop everything up to the merged mining data
    script = script.slice(
      header_idx + merged_mining_header.length, chain_merkle_root.length / 2 + 8
    )

    tx_root_hash = script.slice(0, chain_merkle_root.length / 2).unpack('H*')[0]
    expect(chain_merkle_root).to eq(tx_root_hash)

    merkle_branch_size = script.slice(
      chain_merkle_root.length / 2, 4
    ).unpack('V')[0]
    expect(merkle_branch_size).to eq(1 << aux_pow.chain_branch.length)

    # Choose a pseudo-random slot in the chain merkle tree but have it be fixed
    # for a size/nonce/chain combination.
    nonce = script.slice(chain_merkle_root.length / 2 + 4, 4).unpack('V')[0]
    rand = nonce
    rand = rand * 1_103_515_245 + 12_345
    rand += Bitcoin.network[:auxpow_chain_id]
    rand = rand * 1_103_515_245 + 12_345

    expect(aux_pow.chain_index).to eq(rand % merkle_branch_size)
  end
end
