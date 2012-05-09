#!/usr/bin/env ruby
#
# Relay transaction to the network.
# TODO

require 'socket'
require 'json'

# TODO: use CommandClient

host, port = "127.0.0.1", 9999
if ARGV[0] == "-s"
  host, port = ARGV[1].split(":")
  ARGV.shift; ARGV.shift
end

s = TCPSocket.new("127.0.0.1", 9999)
s.puts ("relay_tx " + ARGF.read.unpack("H*")[0])

res = s.readline
puts JSON::pretty_generate(JSON::parse(res))
s.close
