#!/usr/bin/env ruby
#
# Fetch a transaction from blockexplorer.com and verify all signatures.
#
#  examples/bbe_verify_tx.rb <tx hash> [testnet]
#  examples/bbe_verify_tx.rb f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
# see Bitcoin::P::Tx and Bitcoin::Script.

$:.unshift(File.dirname(__FILE__) + "/../lib")
require 'bitcoin'
require 'open-uri'

tx_hash = ARGV[0]
$testnet = ARGV.select{|i| i.downcase == 'testnet' }[0] ? true : false
$use_coinbase_bbe = ARGV.select{|i| i.downcase == 'coinbase' }[0] ? true : false

# fetch transaction from bbe as json and deserialize into Bitcoin::Protocol::Tx object
def get_tx(hash)
  if $use_coinbase_bbe && !$testnet
    url = "https://coinbase.com/network/tx/%s.json" % [hash]
  else
    url = "http://blockexplorer.com/%srawtx/%s" % [$testnet ? 'testnet/' : '',  hash]
  end
  json = open(url).read
  Bitcoin::Protocol::Tx.from_json(json)
rescue
  nil
end

tx1 = get_tx(tx_hash)

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

  prev_tx = get_tx(txin.previous_output)
  unless prev_tx
    puts "Missing prev_out tx for input #{idx} of tx #{tx_hash}!"
    exit
  end

  result = tx1.verify_input_signature(idx, prev_tx)
  unless result
    puts "Input #{idx} of tx #{tx_hash} is invalid!"
    exit
  end
end

puts "Tx #{tx_hash} is valid."
