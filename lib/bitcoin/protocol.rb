# encoding: ascii-8bit

require 'socket'
require 'digest/sha2'
require 'json'

module Bitcoin
  module Protocol

    # bitcoin/src/main.h
    MAX_INV_SZ = 50000

    # BIP 0031, pong message, is enabled for all versions AFTER this one
    BIP0031_VERSION = 60000
    
    autoload :TxIn,    'bitcoin/protocol/txin'
    autoload :TxOut,   'bitcoin/protocol/txout'
    autoload :Tx,      'bitcoin/protocol/tx'
    autoload :Block,   'bitcoin/protocol/block'
    autoload :Addr,    'bitcoin/protocol/address'
    autoload :Alert,   'bitcoin/protocol/alert'
    autoload :Version, 'bitcoin/protocol/version'
    autoload :AuxPow,  'bitcoin/protocol/aux_pow'

    autoload :Handler, 'bitcoin/protocol/handler'
    autoload :Parser,  'bitcoin/protocol/parser'

    Uniq = rand(0xffffffffffffffff)

    # var_int refers to https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer and is what Satoshi called "CompactSize"
    # BitcoinQT has later added even more compact format called CVarInt to use in its local block storage. CVarInt is not implemented here.
    def self.unpack_var_int(payload)
      case payload.unpack("C")[0] # TODO add test cases
      when 0xfd; payload.unpack("xva*")
      when 0xfe; payload.unpack("xVa*")
      when 0xff; payload.unpack("xQa*") # TODO add little-endian version of Q
      else;      payload.unpack("Ca*")
      end
    end

    def self.unpack_var_int_from_io(io)
      uchar = io.read(1).unpack("C")[0]
      case uchar
      when 0xfd; io.read(2).unpack("v")[0]
      when 0xfe; io.read(4).unpack("V")[0]
      when 0xff; io.read(8).unpack("Q")[0]
      else;      uchar
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
      size, payload = unpack_var_int(payload)
      size > 0 ? (string, payload = payload.unpack("a#{size}a*")) : [nil, payload]
    end

    def self.unpack_var_string_from_io(buf)
      size = unpack_var_int_from_io(buf)
      size > 0 ? buf.read(size) : nil
    end

    def self.pack_var_string(payload)
      pack_var_int(payload.bytesize) + payload
    end

    def self.unpack_var_string_array(payload) # unpacks set<string>
      size, payload = unpack_var_int(payload)
      return [nil, payload] if size == 0
      [(0...size).map{ s, payload = unpack_var_string(payload); s }, payload]
    end

    def self.unpack_var_int_array(payload) # unpacks set<int>
      size, payload = unpack_var_int(payload)
      return [nil, payload] if size == 0
      [(0...size).map{ i, payload = unpack_var_int(payload); i }, payload]
    end

    BINARY = Encoding.find('ASCII-8BIT')

    def self.pkt(command, payload)
      cmd      = command.ljust(12, "\x00")[0...12]
      length   = [payload.bytesize].pack("V")
      checksum = Digest::SHA256.digest(Digest::SHA256.digest(payload))[0...4]
      pkt      = "".force_encoding(BINARY)
      pkt << Bitcoin.network[:magic_head].force_encoding(BINARY) << cmd.force_encoding(BINARY) << length << checksum << payload.force_encoding(BINARY)
    end

    def self.version_pkt(from_id, from=nil, to=nil, last_block=nil, time=nil, user_agent=nil, version=nil)
      opts = if from_id.is_a?(Hash)
        from_id
      else
        STDERR.puts "Bitcoin::Protocol.version_pkt - API deprecated. please change it soon.."
        {
          :nonce => from_id, :from => from, :to => to, :last_block => last_block,
          :time => time, :user_agent => user_agent, :version => version
        }
      end
      version = Protocol::Version.new(opts)
      version.to_pkt
    end

    def self.ping_pkt(nonce = rand(0xffffffff))
      pkt("ping", [nonce].pack("Q"))
    end

    def self.pong_pkt(nonce)
      pkt("pong", [nonce].pack("Q"))
    end

    def self.verack_pkt
      pkt("verack", "")
    end

    TypeLookup = Hash[:tx, 1, :block, 2, nil, 0]

    def self.getdata_pkt(type, hashes)
      return if hashes.size > MAX_INV_SZ
      t = [ TypeLookup[type] ].pack("V")
      pkt("getdata", pack_var_int(hashes.size) + hashes.map{|hash| t + hash[0..32].reverse }.join)
    end

    def self.inv_pkt(type, hashes)
      return if hashes.size > MAX_INV_SZ
      t = [ TypeLookup[type] ].pack("V")
      pkt("inv", pack_var_int(hashes.size) + hashes.map{|hash| t + hash[0..32].reverse }.join)
    end

    DEFAULT_STOP_HASH = "00"*32

    def self.locator_payload(version, locator_hashes, stop_hash)
      payload = [
        [version].pack("V"),
        pack_var_int(locator_hashes.size),
        locator_hashes.map{|l| l.htb_reverse }.join,
        stop_hash.htb_reverse
      ].join
    end

    def self.getblocks_pkt(version, locator_hashes, stop_hash=DEFAULT_STOP_HASH)
      pkt "getblocks",  locator_payload(version, locator_hashes, stop_hash)
    end

    def self.getheaders_pkt(version, locator_hashes, stop_hash=DEFAULT_STOP_HASH)
      pkt "getheaders", locator_payload(version, locator_hashes, stop_hash)
    end

    def self.read_binary_file(path)
      File.open(path, 'rb'){|f| f.read }
    end
  end

  P = Protocol
end
