#!/usr/bin/env ruby

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :testnet3
@store = Bitcoin::Storage.sequel(:db => "postgres://mhanne:password@localhost:5434/testnet3_full")

@store.db[:txout].where(type: 4).each do |txout|
  script = Bitcoin::Script.new(txout[:pk_script])
  if addr = @store.db[:addr][hash160: script.get_hash160]
    addr_id = addr[:id]
  else
    addr_id = @store.db[:addr].insert(hash160: script.get_hash160)
  end

  if addr_txout = @store.db[:addr_txout][addr_id: addr_id, txout_id: txout[:id]]
    # mapping already exists
  else
    @store.db[:addr_txout].insert(addr_id: addr_id, txout_id: txout[:id])
  end
  p [script.to_string, script.get_hash160, addr_id]
end
