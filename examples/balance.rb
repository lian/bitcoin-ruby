#!/usr/bin/env ruby
# 
# Collect all unspent outputs for given address and display balance.
# Optionally display list of transactions.
# 
#  examples/balance.rb <address> [--list]
#  examples/balance.rb 1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :bitcoin
store = Bitcoin::Storage.sequel(:db => "sqlite://bitcoin.db")

address = ARGV.shift

unless Bitcoin.valid_address?(address)
  puts "Address #{address} is invalid."
  exit 1
end


# format value to be displayed
def str_val(val, pre = "")
  ("#{pre}#{"%.8f" % (val / 1e8)}").rjust(20)
end

if ARGV[0] == "--list"
  txouts = store.get_txouts_for_address(address)
  unless txouts.any?
    puts "Address not seen."
    exit
  end

  total = 0
  txouts.each do |txout|
    tx = txout.get_tx
    total += txout.value
    puts "#{tx.hash} |#{str_val(txout.value, '+ ')}  |=> #{str_val(total)}"

    txout.get_tx.in.map(&:get_prev_out).each do |prev_out|
      puts "  from #{prev_out.get_addresses.join(", ")}"
    end
    puts

    if txin = txout.get_next_in
      tx = txin.get_tx
      total -= txout.value
      puts "#{tx.hash} |#{str_val(txout.value, '- ')}  |=> #{str_val(total)}"
      txin.get_tx.out.each do |out|
        puts "  to #{out.get_addresses.join(", ")}"
      end
      puts
    end
  end
end

hash160 = Bitcoin.hash160_from_address(address)
balance = store.get_balance(hash160)
puts "Balance: %.8f" % (balance / 1e8)
