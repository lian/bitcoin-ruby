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

    VERSION = 60001

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
      size, payload = unpack_var_int(payload)
      size > 0 ? (string, payload = payload.unpack("a#{size}a*")) : [nil, payload]
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


    def self.pkt(command, payload)
      cmd      = command.ljust(12, "\x00")[0...12]
      length   = [payload.bytesize].pack("I")
      checksum = Digest::SHA256.digest(Digest::SHA256.digest(payload))[0...4]

      [Bitcoin.network[:magic_head], cmd, length, checksum, payload].join
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
      return if hashes.size >= 256
      t = [ TypeLookup[type] ].pack("I")
      pkt("getdata", [hashes.size].pack("C") + hashes.map{|hash| t + hash[0..32].reverse }.join)
    end

    def self.inv_pkt(type, hashes)
      return if hashes.size >= 256
      t = [ TypeLookup[type] ].pack("I")
      pkt("inv", [hashes.size].pack("C") + hashes.map{|hash| t + hash[0..32].reverse }.join)
    end

    DEFAULT_STOP_HASH = "00"*32

    def self.locator_payload(locator_hashes, stop_hash)
      payload = [
        Bitcoin.network[:magic_head],
        pack_var_int(locator_hashes.size),
        locator_hashes.map{|l| htb(l).reverse }.join,
        htb(stop_hash).reverse
      ].join
    end

    def self.getblocks_pkt(locator_hashes, stop_hash=DEFAULT_STOP_HASH)
      pkt "getblocks",  locator_payload(locator_hashes, stop_hash)
    end

    def self.getheaders_pkt(locator_hashes, stop_hash=DEFAULT_STOP_HASH)
      pkt "getheaders", locator_payload(locator_hashes, stop_hash)
    end

    def self.hth(h); h.unpack("H*")[0]; end
    def self.htb(h); [h].pack("H*"); end

    def self.read_binary_file(path)
      File.open(path, 'rb'){|f| f.read }
    end
  end

  P = Protocol
end
