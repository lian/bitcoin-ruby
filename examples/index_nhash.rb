#!/usr/bin/env ruby

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :testnet3
@store = Bitcoin::Storage.sequel(:db => "postgres://mhanne:password@localhost:5434/testnet3_full")

#@store.db.execute "DROP INDEX tx_nhash_index"

def process_block blk
  print "\r#{blk.hash} - #{blk.depth}"
  blk.tx.each do |tx|
    @store.db[:tx].where(hash: tx.hash.htb.blob).update(nhash: tx.nhash.htb.blob)
  end
end

blk = @store.get_block_by_depth(0)
process_block(blk)
while blk = blk.get_next_block
  process_block(blk)
end

@store.db.execute "CREATE INDEX tx_nhash_index ON tx (nhash)"
