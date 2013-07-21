#!/usr/bin/env ruby
#
# Connect to a node's command socket, monitor incoming payments to one address
# and forward everything to another address.
# Needs the private key of the receiving address (to sign new tx) and the forwarding
# address where payments are sent to.
# Note how the private key does NOT have to be passed to the node, we just sign the
# sig_hash ourselves.
#
#  examples/forwarder.rb <base58_privkey> <forwarding_address>
#  examples/forwarder.rb KyZsiZiFyewBswJpdYywz4b5sif252iN5zZQjGzPVVgAsGYyMk8a 12bL22Pynmp7pDtDqD2w9iP7dRzdM1gNUd

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'eventmachine'
require 'bitcoin'

Bitcoin.network = :testnet3

EM.run do

  # key/address where people can send money
  KEY = Bitcoin::Key.from_base58(ARGV[0])

  # address where received money is forwarded to
  FORWARD = ARGV[1]

  # number of confirmations tx need before being forwarded
  CONFIRMATIONS = 1

  # list of already forwarded txs, to prevent duplicates
  FORWARDED_TXS = []

  Bitcoin::Network::CommandClient.connect("127.0.0.1", 9999) do

    on_connected do
      request("monitor", "output", "output_#{CONFIRMATIONS}")

      puts "Running bitcoin forwarder on address #{KEY.addr}."
      puts "Forwarding every incoming payment to #{FORWARD}."
    end

    on_output do |tx_hash, recipient_addr, value, confirmations|
      if recipient_addr == KEY.addr
        if confirmations >= CONFIRMATIONS
          next  if FORWARDED_TXS.include?(tx_hash)
          FORWARDED_TXS << tx_hash
          puts "Payment of #{value.to_f/1e8} BTC confirmed. Forwarding..."

          # Note: We could also pass KEY.priv instead of KEY.addr here.
          # Then we would get the complete tx in one step without calling "assemble_tx".
          request("create_tx", [KEY.addr], [[FORWARD, value]])
        else
          puts "Received unconfirmed payment of #{value.to_f/1e8} BTC."
        end
      end
    end

    on_create_tx do |unsigned_tx, sig_hashes|
      sig_pubkeys = sig_hashes.map do |sig_hash, address|
        [KEY.sign(sig_hash.htb).hth, KEY.pub]
      end
      request("assemble_tx", unsigned_tx, sig_pubkeys)
    end

    on_assemble_tx do |tx_in_hex|
      tx = Bitcoin::P::Tx.new(tx_in_hex.htb)
      puts "Relaying tx #{tx.hash}..."
      request("relay_tx", tx_in_hex)
    end

  end

end
