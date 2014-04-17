#!/usr/bin/env ruby
#
# Connect to a random peer and download the first 500 blocks.
#
#  examples/connect.rb [testnet]
#
# see Bitcoin::Connection and Bitcoin::Protocol.

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin/connection'

Bitcoin::network = ARGV[0] || :bitcoin

class RawJSON_Connection < Bitcoin::Connection
  def on_tx(tx)
    p ['tx', tx.hash, Time.now]
    # puts tx.to_json
  end

  def on_block(block)
    p ['block', block.hash, Time.now]
    # puts block.to_json
  end
end

EM.run do

  host = '127.0.0.1'
  #host = '217.157.1.202'

  connections = []
  #RawJSON_Connection.connect(host, 8333, connections)

  RawJSON_Connection.connect_random_from_dns(connections)

end
