#!/usr/bin/env ruby
#

$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

Bitcoin.network = :testnet
node = Bitcoin::Network::Node.new(:network => :bitcoin, :storage => :dummy)
node.run
