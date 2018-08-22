# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

# following test cases are borrowed from
# https://github.com/bitcoinj/bitcoinj/blob/master/core/src/test/java/org/bitcoinj/core/FilteredBlockAndPartialMerkleTreeTests.java
describe 'Bitcoin::Protocol::PartialMerkleTree' do
  it 'initialize' do
    hashes = %w[
      4c30b63cfcdc2d35e3329421b9805ef0c6565d35381ca857762ea0b3a5a128bb
      ca5065ff9617cbcba45eb23726df6498a9b9cafed4f54cbab9d227b0035ddefb
      bb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181
      d77706be8b1dcc91112eada86d424e2d0a8907c3488b6e44fda5a74a25cbc7d6
      bb4fa04245f4ac8a1a571d5537eac24adca1454d65eda446055479af6c6d4dd3
      c9ab658448c10b6921b7a4ce3021eb22ed6bb6a7fde1e5bcc4b1db6615c6abc5
      ca042127bfaf9f44ebce29cb29c6df9d05b47f35b2edff4f0064b578ab741fa7
      8276222651209fe1a2c4c0fa1c58510aec8b090dd1eb1f82f9d261b8273b525b
    ].map(&:htb)

    tree = Bitcoin::Protocol::PartialMerkleTree.new(12, hashes, 'ff1a'.htb)
    tree.assign_value

    tx_hashes = Set.new(tree.tx_hashes)
    # following 6 are leaves (tx_hash) of merkle tree
    expect(tx_hashes)
      .to include('bb28a1a5b3a02e7657a81c38355d56c6f05e80b9219432e3352ddcfc3cb6304c')
    expect(tx_hashes)
      .to include('fbde5d03b027d2b9ba4cf5d4fecab9a99864df2637b25ea4cbcb1796ff6550ca')
    expect(tx_hashes)
      .to include('8131ffb0a2c945ecaf9b9063e59558784f9c3a74741ce6ae2a18d0571dac15bb')
    expect(tx_hashes)
      .to include('c5abc61566dbb1c4bce5e1fda7b66bed22eb2130cea4b721690bc1488465abc9')
    expect(tx_hashes)
      .to include('d6c7cb254aa7a5fd446e8b48c307890a2d4e426da8ad2e1191cc1d8bbe0677d7')
    expect(tx_hashes)
      .to include('a71f74ab78b564004fffedb2357fb4059ddfc629cb29ceeb449fafbf272104ca')
    # following 2 are edge node of merkle tree
    expect(tx_hashes)
      .not_to include('d34d6d6caf79540546a4ed654d45a1dc4ac2ea37551d571a8aacf44542a04fbb')
    expect(tx_hashes)
      .not_to include('5b523b27b861d2f9821febd10d098bec0a51581cfac0c4a2e19f205126227682')

    expect(tree.root.value)
      .to eq('7fe79307aeb300d910d9c4bec5bacb4c7e114c7dfd6789e19f3a733debb3bb6a')
  end
end
