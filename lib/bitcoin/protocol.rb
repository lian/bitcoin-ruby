require 'socket'
require 'digest/sha2'
require 'json'

module Bitcoin
  module Protocol

    autoload :Tx,      'bitcoin/protocol/tx'
    autoload :Block,   'bitcoin/protocol/block'
    autoload :Addr,    'bitcoin/protocol/address'

    autoload :Handler, 'bitcoin/protocol/handler'
    autoload :Parser,  'bitcoin/protocol/parser'

    VERSION = 31900

    DNS_Seed = [ "bitseed.xf2.org", "bitseed.bitcoin.org.uk" ]
    Uniq = rand(0xffffffffffffffff)

    def self.read_var_int(payload)
      case payload.unpack("C")[0] # TODO add test cases
      when 0xfd; payload.unpack("xva*")
      when 0xfe; payload.unpack("xVa*")
      when 0xff; payload.unpack("xQa*") # TODO add little-endian version of Q
      else;      payload.unpack("Ca*")
      end
    end

    def self.pkt(command, payload)
      cmd      = command.ljust(12, "\x00")[0...12]
      length   = [payload.bytesize].pack("I")
      checksum = ['version', 'verack'].include?(command) ?
        "" : Digest::SHA256.digest(Digest::SHA256.digest(payload))[0...4]

      [Bitcoin::network[:magic_head], cmd, length, checksum, payload].join
    end

    def self.version_pkt(from_id, from, to, last_block=nil, time=nil)
      ver, services = [Bitcoin::Protocol::VERSION].pack("I"), [1].pack("Q")
      time = [ time || Time.now.tv_sec ].pack("Q")
      payload = [
        ver, services, time, 
        network_address(from),  # me
        network_address(to),    # you
        [ from_id ].pack("Q"),
        "\x00",
        [last_block || 0].pack("I")
      ]
      pkt("version", payload.join)
    end

    def self.verack_pkt
      pkt("verack", "")
    end

    def self.getdata_pkt(type, hashes)
      return if hashes.size >= 256
      t = case type
          when :tx;    1
          when :block; 2
          else         0
          end
      pkt("getdata", [hashes.size].pack("C") +
        hashes.map{|hash| [t].pack("I") + hash[0..32].reverse }.join)
    end

    def self.inv_pkt(type, hashes)
      return if hashes.size >= 256
      t = case type
          when :tx;    1
          when :block; 2
          else         0
          end
      pkt("inv", [hashes.size].pack("C") +
        hashes.map{|hash| [t].pack("I") + hash[0..32].reverse }.join)
    end

    def self.network_address(addr)
      host, port = addr.split(":")
      port = port ? port.to_i : 8333
      sockaddr = Socket.pack_sockaddr_in(port, host)
      #raise "invalid IPv4 Address: #{addr}" unless sockaddr[0...2] == "\x02\x00"
      port, host = sockaddr[2...4], sockaddr[4...8]
      [[1].pack("Q"), "\x00"*10, "\xFF\xFF",  host, port].join
    end

  end
end
