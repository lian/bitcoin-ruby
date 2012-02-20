require 'socket'
require 'digest/sha2'
require 'json'

module Bitcoin
  module Protocol

    autoload :TxIn,    'bitcoin/protocol/txin'
    autoload :TxOut,   'bitcoin/protocol/txout'
    autoload :Tx,      'bitcoin/protocol/tx'
    autoload :Block,   'bitcoin/protocol/block'
    autoload :Addr,    'bitcoin/protocol/address'
    autoload :Alert,   'bitcoin/protocol/alert'
    autoload :Version, 'bitcoin/protocol/version'

    autoload :Handler, 'bitcoin/protocol/handler'
    autoload :Parser,  'bitcoin/protocol/parser'

    VERSION = 31900

    DNS_Seed = [ "bitseed.xf2.org", "bitseed.bitcoin.org.uk" ]
    Uniq = rand(0xffffffffffffffff)

    def self.unpack_var_int(payload)
      case payload.unpack("C")[0] # TODO add test cases
      when 0xfd; payload.unpack("xva*")
      when 0xfe; payload.unpack("xVa*")
      when 0xff; payload.unpack("xQa*") # TODO add little-endian version of Q
      else;      payload.unpack("Ca*")
      end
    end

    def self.pack_var_int(i)
      if    i <  0xfd;                [      i].pack("C")
      elsif i <= 0xffff;              [0xfd, i].pack("Cv")
      elsif i <= 0xffffffff;          [0xfe, i].pack("CV")
      elsif i <= 0xffffffffffffffff;  [0xff, i].pack("CQ")
      else raise "int(#{i}) too large!"
      end
    end

    def self.unpack_var_string(payload)
      size, payload = payload.unpack("Ca*")
      size > 0 ? (string, payload = payload.unpack("a#{size}a*")) : [nil, payload]
    end

    def self.pack_var_string(payload)
      [payload.bytesize].pack("C") + payload
    end

    def self.pkt(command, payload)
      cmd      = command.ljust(12, "\x00")[0...12]
      length   = [payload.bytesize].pack("I")
      checksum = Digest::SHA256.digest(Digest::SHA256.digest(payload))[0...4]

      [Bitcoin.network[:magic_head], cmd, length, checksum, payload].join
    end

    def self.version_pkt(from_id, from, to, last_block=nil, time=nil, user_agent=nil)
      payload = Protocol::Version.build_payload(from_id, from, to, last_block, time, user_agent)
      pkt("version", payload)
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

  end

  P = Protocol
end
