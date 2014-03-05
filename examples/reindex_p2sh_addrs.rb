#!/usr/bin/env ruby

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :testnet3
@store = Bitcoin::Storage.sequel(:db => "postgres://mhanne:password@localhost:5434/testnet3_full")
# @store = Bitcoin::Storage.sequel(:db => "postgres:/testnet3")

puts "move namecoin types up by one to make room for op_return"
if Bitcoin.network_name == :namecoin
  @store.db.run "UPDATE txout SET type = 8 WHERE type = 7"
  @store.db.run "UPDATE txout SET type = 7 WHERE type = 6"
  @store.db.run "UPDATE txout SET type = 6 WHERE type = 5"
end

puts "create missing p2sh output <-> address mappings"
@store.db[:txout].where(type: 4).each do |txout|
  script = Bitcoin::Script.new(txout[:pk_script])
  if addr = @store.db[:addr][hash160: script.get_hash160]
    addr_id = addr[:id]
  else
    addr_id = @store.db[:addr].insert(hash160: script.get_hash160)
  end

  if addr_txout = @store.db[:addr_txout][addr_id: addr_id, txout_id: txout[:id]]
    # mapping already exists
    print "e"
  else
    print "C"
    @store.db[:addr_txout].insert(addr_id: addr_id, txout_id: txout[:id])
  end
end

puts
puts "scan all txouts of unknown type and check if they are op_returns"
@store.db[:txout].where(type: 0).each do |txout|
  if Bitcoin::Script.new(txout[:pk_script]).is_op_return?
    print "C"
    @store.db[:txout].where(id: txout[:id]).update(type: 5)
  else
    print "s"
  end
end
