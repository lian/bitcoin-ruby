#!/usr/bin/env ruby
#
# Fetch a transaction and all its previous outputs from local storage and verify signatures.
#
#  examples/verify_tx.rb <tx_hash>
#  examples/verify_tx.rb f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
#
# see Bitcoin::Protocol::Tx and Bitcoin::Script.
# Note: For this to work, you need to have the transactions in your storage. see NODE.
# Note: There is also Bitcoin::Validation::Tx which validates a lot more than signatures.

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :bitcoin
store = Bitcoin::Storage.sequel(:db => "sqlite://bitcoin.db")

tx_hash = ARGV.shift

tx1 = store.get_tx(tx_hash)

unless tx1
  puts "Tx #{tx_hash} not found."
  exit
end

if tx1.in.all?{|txin| txin.coinbase? }
  puts "Tx #{tx_hash} is a coinbase transaction. Check the block instead."
  exit
end

tx1.in.each_with_index do |txin, idx|
  if txin.coinbase?
    puts "skipping coinbase transaction input.."; next
  end

  prev_tx = txin.get_prev_out.get_tx
  if prev_tx
    puts "Found prev tx #{prev_tx.hash}"
    txout = prev_tx.out[txin.prev_out_index]
    script = Bitcoin::Script.new(txout.pk_script)
    puts "Output Script: #{script.to_string}"
  else
    puts "Missing prev tx for input #{idx}!"
    exit
  end

  result = tx1.verify_input_signature(idx, prev_tx)
  if result
    puts "Valid signature for input #{idx}."
  else
    puts "Signature for input #{idx} is invalid!"
    exit
  end
end

puts "Tx #{tx_hash} is valid."
