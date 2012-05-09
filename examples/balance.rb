#!/usr/bin/env ruby
# 
# Collect all unspent outputs for given address and display balance.
# Optionally display list of transactions.
# 
#  ruby examples/balance.rb <address> [--list]
#  ruby examples/balance.rb -s sequel::postgres:/bitcoin -l moz14kFmgHPszRvS6rvhfEVYmx4RbcNMfH

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :bitcoin
store = Bitcoin::Storage.sequel(:db => "sqlite://bitcoin.db")

address = ARGV.shift

unless Bitcoin.valid_address?(address)
  puts "Address #{address} is invalid."
  exit 1
end

script = Bitcoin::Script.to_address_script(address)
txouts = store.get_txouts_for_pk_script(script)
unless txouts.any?
  puts "Address not seen."
  exit
end

# format value to be displayed
def str_val(val, pre = "")
  ("#{pre}#{"%.8f" % (val / 1e8)}").rjust(20)
end

if ARGV[0] == "--list"
  total = 0
  txouts.each do |txout|
    tx = txout.get_tx
    total += txout.value
    puts "#{tx.hash} |#{str_val(txout.value, '+ ')}  |=> #{str_val(total)}"

    txout.get_tx.in.map(&:get_prev_out).each do |prev_out|
      puts "  <- #{prev_out.get_addresses.join(", ")}"
    end
    puts

    if txin = txout.get_next_in
      tx = txin.get_tx
      total -= txout.value
      puts "#{tx.hash} |#{str_val(txout.value, '- ')}  |=> #{str_val(total)}"
      txin.get_tx.out.each do |out|
        puts "  -> #{out.get_addresses.join(", ")}"
      end
      puts
    end
  end
end

balance = store.get_balance(address)
puts "Balance: %.8f" % (balance / 1e8)
