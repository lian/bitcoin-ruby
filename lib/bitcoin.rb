# Bitcoin Utils and Network Protocol in Ruby.

require 'digest/sha2'
require 'digest/rmd160'
require 'openssl'


module Bitcoin

  autoload :Connection, 'bitcoin/connection'
  autoload :Protocol,   'bitcoin/protocol'
  autoload :P,          'bitcoin/protocol'
  autoload :Script,     'bitcoin/script'
  autoload :VERSION,    'bitcoin/version'
  autoload :Storage,    'bitcoin/storage/storage'
  autoload :Logger,     'bitcoin/logger'
  autoload :Key,        'bitcoin/key'
  autoload :Config,     'bitcoin/config'
  autoload :Builder,    'bitcoin/builder'

  module Network
    autoload :ConnectionHandler,  'bitcoin/network/connection_handler'
    autoload :CommandHandler,     'bitcoin/network/command_handler'
    autoload :CommandClient,     'bitcoin/network/command_client'
    autoload :Node,               'bitcoin/network/node'
  end

  module Wallet
    autoload :KeyGenerator,          'bitcoin/wallet/keygenerator'
    autoload :SimpleKeyStore,        'bitcoin/wallet/keystore'
    autoload :DeterministicKeyStore, 'bitcoin/wallet/keystore'
    autoload :SimpleCoinSelector,    'bitcoin/wallet/coinselector'
    autoload :Wallet,                'bitcoin/wallet/wallet'
    autoload :TxDP,                'bitcoin/wallet/txdp'
  end

  module Gui
    autoload :Gui,        'bitcoin/gui/gui'
    autoload :Connection, 'bitcoin/gui/connection'
  end

  def self.require_dependency name, opts = {}
    begin
      require name.to_s
    rescue LoadError
      print "Cannot load #{opts[:exit] == false ? 'optional' : 'required'} dependency '#{name}'"
      (opts[:gem] == false) ? puts("") :
        puts(" - install with `gem install #{opts[:gem] || name}`")
      puts opts[:message]  if opts[:message]
      exit 1  unless opts[:exit] == false
      return false
    end
    true
  end

  module Util

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end

    def address_version; Bitcoin.network[:address_version]; end
    def p2sh_version; Bitcoin.network[:p2sh_version]; end

    # hash160 is a 20 bytes (160bits) rmd610-sha256 hexdigest.
    def hash160(hex)
      bytes = [hex].pack("H*")
      Digest::RMD160.hexdigest Digest::SHA256.digest(bytes)
    end

    # checksum is a 4 bytes sha256-sha256 hexdigest.
    def checksum(hex)
      b = [hex].pack("H*") # unpack hex
      Digest::SHA256.hexdigest( Digest::SHA256.digest(b) )[0...8]
    end

    # verify base58 checksum for given +base58+ data.
    def base58_checksum?(base58)
      hex = decode_base58(base58) rescue nil
      return false unless hex
      Bitcoin.checksum( hex[0...42] ) == hex[-8..-1]
    end
    alias :address_checksum? :base58_checksum?

    # check if given +address+ is valid.
    # this means having a correct version byte, length and checksum.
    def valid_address?(address)
      hex = decode_base58(address) rescue nil
      return false unless hex && hex.bytesize == 50
      return false unless [address_version, p2sh_version].include?(hex[0...2])
      address_checksum?(address)
    end

    # get hash160 for given +address+. returns nil if address is invalid.
    def hash160_from_address(address)
      return nil  unless valid_address?(address)
      decode_base58(address)[2...42]
    end

    # get type of given +address+.
    def address_type(address)
      return nil unless valid_address?(address)
      case decode_base58(address)[0...2]
      when address_version; :hash160
      when p2sh_version;    :p2sh
      end
    end

    def sha256(hex)
      Digest::SHA256.hexdigest([hex].pack("H*"))
    end

    def hash160_to_address(hex)
      hex = address_version + hex
      encode_base58(hex + checksum(hex))
    end

    def pubkey_to_address(pubkey)
      hash160_to_address( hash160(pubkey) )
    end

    def int_to_base58(int_val, leading_zero_bytes=0)
      alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      base58_val, base = '', alpha.size
      while int_val > 0
        int_val, remainder = int_val.divmod(base)
        base58_val = alpha[remainder] + base58_val
      end
      base58_val
    end

    def base58_to_int(base58_val)
      alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      int_val, base = 0, alpha.size
      base58_val.reverse.each_char.with_index do |char,index|
        raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)
        int_val += char_index*(base**index)
      end
      int_val
    end

    def encode_base58(hex)
      leading_zero_bytes  = (hex.match(/^([0]+)/) ? $1 : '').size / 2
      ("1"*leading_zero_bytes) + int_to_base58( hex.to_i(16) )
    end


    def decode_base58(base58_val)
      s = base58_to_int(base58_val).to_s(16); s = (s.bytesize.odd? ? '0'+s : s)
      s = '' if s == '00'
      leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
      s = ("00"*leading_zero_bytes) + s  if leading_zero_bytes > 0
      s
    end
    alias_method :base58_to_hex, :decode_base58

    # target compact bits (int) to bignum hex
    def decode_compact_bits(bits)
      bytes = Array.new(size=((bits >> 24) & 255), 0)
      bytes[0] = (bits >> 16) & 255 if size >= 1
      bytes[1] = (bits >>  8) & 255 if size >= 2
      bytes[2] = (bits      ) & 255 if size >= 3
      bytes.pack("C*").unpack("H*")[0].rjust(64, '0')
    end

    # target bignum hex to compact bits (int)
    def encode_compact_bits(target)
      bytes = OpenSSL::BN.new(target, 16).to_mpi
      size = bytes.size - 4
      nbits = size << 24
      nbits |= (bytes[4] << 16) if size >= 1
      nbits |= (bytes[5] <<  8) if size >= 2
      nbits |= (bytes[6]      ) if size >= 3
      nbits
    end

    def decode_target(target_bits)
      case target_bits
      when Fixnum
        [ decode_compact_bits(target_bits).to_i(16), target_bits ]
      when String
        [ target_bits.to_i(16), encode_compact_bits(target_bits) ]
      end
    end

    def bitcoin_elliptic_curve
      ::OpenSSL::PKey::EC.new("secp256k1")
    end

    def generate_key
      key = bitcoin_elliptic_curve.generate_key
      inspect_key( key )
    end

    def inspect_key(key)
      [ key.private_key_hex, key.public_key_hex ]
    end

    def generate_address
      prvkey, pubkey = generate_key
      [ pubkey_to_address(pubkey), prvkey, pubkey, hash160(pubkey) ]
    end

    def bitcoin_hash(hex)
      Digest::SHA256.digest(
        Digest::SHA256.digest( [hex].pack("H*").reverse )
      ).reverse.unpack("H*")[0]
    end

    def bitcoin_mrkl(a, b); bitcoin_hash(b + a); end

    def block_hash(prev_block, mrkl_root, time, bits, nonce, ver)
      h = "%08x%08x%08x%064s%064s%08x" %
            [nonce, bits, time, mrkl_root, prev_block, ver]
      bitcoin_hash(h)
    end

    def hash_mrkl_tree(tx)
      chunks = [ tx.dup ]
      while chunks.last.size >= 2
        chunks << chunks.last.each_slice(2).map{|i|
          Bitcoin.bitcoin_mrkl( i[0], i[1] || i[0] )
        }
      end
      chunks.flatten
    end


    def sign_data(key, data)
      key.dsa_sign_asn1(data)
    end

    def verify_signature(hash, signature, public_key)
      key  = bitcoin_elliptic_curve
      key.public_key = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
      key.dsa_verify_asn1(hash, signature)
    rescue OpenSSL::PKey::ECError, OpenSSL::PKey::EC::Point::Error
      false
    end 

    def open_key(private_key, public_key=nil)
      key  = bitcoin_elliptic_curve
      key.private_key = ::OpenSSL::BN.from_hex(private_key)
      public_key = regenerate_public_key(private_key) unless public_key
      key.public_key  = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
      key
    end

    def regenerate_public_key(private_key)
      Bitcoin::OpenSSL_EC.regenerate_key(private_key)[1]
    end


    RETARGET_INTERVAL = 2016

    # block count when the next retarget will take place.
    def block_next_retarget(block_height)
      (block_height + (RETARGET_INTERVAL-block_height.divmod(RETARGET_INTERVAL).last)) - 1
    end

    # current difficulty as a multiple of the minimum difficulty (highest target).
    def block_difficulty(target_nbits)
      # max_target      = 0x00000000ffff0000000000000000000000000000000000000000000000000000
      # current_target  = Bitcoin.decode_compact_bits(target_nbits).to_i(16)
      # "%.7f" % (max_target / current_target.to_f)
      bits, max_body, scaland = target_nbits, Math.log(0x00ffff), Math.log(256)
      "%.7f" % Math.exp(max_body - Math.log(bits&0x00ffffff) + scaland * (0x1d - ((bits&0xff000000)>>24)))
    end

    # average number of hashes required to win a block with the current target. (nbits)
    def block_hashes_to_win(target_nbits)
      current_target  = Bitcoin.decode_compact_bits(target_nbits).to_i(16)
      0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff / current_target
    end

    # probability of a single hash solving a block with the current difficulty.
    def block_probability(target_nbits)
      current_target  = Bitcoin.decode_compact_bits(target_nbits).to_i(16)
      "%.55f" % (current_target.to_f / 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    end

    # average time to find a block in seconds with the current target. (nbits)
    def block_average_hashing_time(target_nbits, hashes_per_second)
      block_hashes_to_win(target_nbits) / hashes_per_second
    end

    # shows the total number of Bitcoins in circulation, reward era and reward in that era.
    def blockchain_total_btc(height)
      reward, interval = 5000000000, 210000
      total_btc = reward
      reward_era, remainder = (height).divmod(interval)
      reward_era.times{
        total_btc += interval * reward
        reward = reward / 2
      }
      total_btc += remainder * reward
      [total_btc, reward_era+1, reward, height]
    end

    def block_creation_reward(block_height)
      5000000000 / (2 ** (block_height / 210000.0).floor)
    end
  end

  module ::OpenSSL
    class BN
      def self.from_hex(hex); new(hex, 16); end
      def to_hex; to_i.to_s(16); end
      def to_mpi; to_s(0).unpack("C*"); end
    end
    class PKey::EC
      def private_key_hex; private_key.to_hex.rjust(64, '0'); end
      def public_key_hex;  public_key.to_hex.rjust(130, '0'); end
    end
    class PKey::EC::Point
      def self.from_hex(group, hex)
        new(group, BN.from_hex(hex))
      end
      def to_hex; to_bn.to_hex; end
      def self.bn2mpi(hex) BN.from_hex(hex).to_mpi; end
    end
  end

  autoload :OpenSSL_EC, "bitcoin/ffi/openssl"


  extend Util

  @network = :bitcoin

  def self.network
    NETWORKS[@network]
  end

  def self.network= name
    @network = name.to_sym
  end

  NETWORKS = {
    :bitcoin => {
      :magic_head => "\xF9\xBE\xB4\xD9",
      :address_version => "00",
      :p2sh_version => "05",
      :privkey_version => "80",
      :default_port => 8333,
      :dns_seeds => ["bitseed.xf2.org", "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org", "seed.bitcoin.sipa.be"],
      :genesis_hash => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      :proof_of_work_limit => 0x1d00ffff,
      :known_nodes => [
        'relay.eligius.st',
        'mining.bitcoin.cz',
        'bitcoins.lc',
        'blockchain.info',
        'blockexplorer.com',
      ]
    },
    :testnet => {
      :magic_head => "\xFA\xBF\xB5\xDA",
      :address_version => "6f",
      :p2sh_version => "c4",
      :privkey_version => "ef",
      :default_port => 18333,
      :dns_seeds => ["testseed.bitcoin.interesthings.de"],
      :genesis_hash => "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008",
      :proof_of_work_limit => 0x1d07fff8,
      :known_nodes => []
    }
  }
  
end
