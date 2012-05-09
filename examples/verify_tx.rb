#!/usr/bin/env ruby
#
# Fetch a transaction and all its previous outputs from local storage and verify signatures.
#
#  verify_tx.rb [options] <tx_hash>
#  ruby examples/verify_tx.rb -s sequel::postgres:/bitcoin 0f6741210a02e196ca5f5ad17f684968623546c1accdbcb701a668a51a7ba9fd

Note: For this to work, you obviously need to have the transactions in your storage.

#
$:.unshift( File.expand_path("../../lib", __FILE__) )

require 'bitcoin'
require 'optparse'

options = {
  :network => "testnet",
  :storage => "dummy",
}
optparse = OptionParser.new do|opts|
  opts.banner = "Usage: bitcoin_verify_tx [options] <tx hash>"

  opts.on("-n", "--network [NETWORK]", "User Network (default: testnet)") do |network|
    options[:network] = network
  end

  opts.on("-s", "--storage [BACKEND::CONFIG]", "Use storage backend (default: 'dummy')") do |storage|
    options[:storage] = storage
  end

  opts.on( '-h', '--help', 'Display this screen' ) do
    puts opts
    exit
  end
end
optparse.parse!


Bitcoin.network = options[:network]
puts "Using network #{options[:network]}"
backend, config = options[:storage].split('::')
store = Bitcoin::Storage.send(backend, :db => config)
puts "Using #{backend} store #{config}"

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
