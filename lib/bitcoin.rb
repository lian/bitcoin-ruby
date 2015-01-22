# encoding: ascii-8bit
# Bitcoin Utils and Network Protocol in Ruby.

require 'digest/sha2'
require 'digest/rmd160'
require 'openssl'
require 'securerandom'

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
  autoload :Validation, 'bitcoin/validation'

  autoload :Dogecoin,   'bitcoin/dogecoin'
  autoload :Litecoin,   'bitcoin/litecoin'

  autoload :ContractHash,   'bitcoin/contracthash'

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

  def self.require_dependency name, opts = {}
    begin
      require name.to_s
    rescue LoadError
      return false if name.to_s == "log4r"
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
      checksum( hex[0...42] ) == hex[-8..-1]
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

    # check if given +pubkey+ is valid.
    def valid_pubkey?(pubkey)
      ::OpenSSL::PKey::EC::Point.from_hex(bitcoin_elliptic_curve.group, pubkey)
      true
    rescue OpenSSL::PKey::EC::Point::Error
      false
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
      encode_address hex, address_version
    end

    def hash160_to_p2sh_address(hex)
      encode_address hex, p2sh_version
    end

    def encode_address(hex, version)
      hex = version + hex
      encode_base58(hex + checksum(hex))
    end

    def pubkey_to_address(pubkey)
      hash160_to_address( hash160(pubkey) )
    end

    def pubkeys_to_p2sh_multisig_address(m, *pubkeys)
      redeem_script = Bitcoin::Script.to_p2sh_multisig_script(m, *pubkeys).last
      return Bitcoin.hash160_to_p2sh_address(Bitcoin.hash160(redeem_script.hth)), redeem_script
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
      if Bitcoin.network_project == :dogecoin
        bytes = Array.new(size=((bits >> 24) & 255), 0)
        bytes[0] = (bits >> 16) & 0x7f if size >= 1
        bytes[1] = (bits >>  8) & 255 if size >= 2
        bytes[2] = (bits      ) & 255 if size >= 3
        target = bytes.pack("C*").unpack("H*")[0].rjust(64, '0')
        # Bit number 24 represents the sign
        if (bits & 0x00800000) != 0
          "-" + target
        else
          target
        end
      else
        bytes = Array.new(size=((bits >> 24) & 255), 0)
        bytes[0] = (bits >> 16) & 255 if size >= 1
        bytes[1] = (bits >>  8) & 255 if size >= 2
        bytes[2] = (bits      ) & 255 if size >= 3
        bytes.pack("C*").unpack("H*")[0].rjust(64, '0')
      end
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
      ).reverse.bth
    end

    def bitcoin_byte_hash(bytes)
      Digest::SHA256.digest(Digest::SHA256.digest(bytes))
    end

    def bitcoin_mrkl(a, b); bitcoin_hash(b + a); end

    def block_hash(prev_block, mrkl_root, time, bits, nonce, ver)
      h = "%08x%08x%08x%064s%064s%08x" %
            [nonce, bits, time, mrkl_root, prev_block, ver]
      bitcoin_hash(h)
    end

    def litecoin_hash(hex)
      bytes = [hex].pack("H*").reverse
      begin
        require "scrypt" unless defined?(::SCrypt)
        hash = SCrypt::Engine.__sc_crypt(bytes, bytes, 1024, 1, 1, 32)
      rescue LoadError
        hash = Litecoin::Scrypt.scrypt_1024_1_1_256_sp(bytes)
      end
      hash.reverse.unpack("H*")[0]
    end

    def block_scrypt_hash(prev_block, mrkl_root, time, bits, nonce, ver)
      h = "%08x%08x%08x%064s%064s%08x" %
            [nonce, bits, time, mrkl_root, prev_block, ver]
      litecoin_hash(h)
    end

    # get merkle tree for given +tx+ list.
    def hash_mrkl_tree(tx)
      return [nil]  if tx != tx.uniq
      chunks = [ tx.dup ]
      while chunks.last.size >= 2
        chunks << chunks.last.each_slice(2).map {|a, b| bitcoin_mrkl( a, b || a ) }
      end
      chunks.flatten
    end

    # get merkle branch connecting given +target+ to the merkle root of +tx+ list
    def hash_mrkl_branch(tx, target)
      return [ nil ]  if tx != tx.uniq
      branch, chunks = [], [ tx.dup ]
      while chunks.last.size >= 2
        chunks << chunks.last.each_slice(2).map {|a, b|
          hash = bitcoin_mrkl( a, b || a )
          next hash  unless [a, b].include?(target)
          branch << (a == target ? (b || a) : a)
          target = hash
        }
      end
      branch
    end

    # get merkle root from +branch+ and +target+.
    def mrkl_branch_root(branch, target, idx)
      branch.each do |hash|
        a, b = *( idx & 1 == 0 ? [target, hash] : [hash, target] )
        idx >>= 1;
	target = bitcoin_mrkl( a, b )
      end
      target
    end

    def sign_data(key, data)
      sig = key.dsa_sign_asn1(data)
      if Script.is_low_der_signature?(sig)
        sig
      else
        Bitcoin::OpenSSL_EC.signature_to_low_s(sig)
      end
    end

    def verify_signature(hash, signature, public_key)
      key  = bitcoin_elliptic_curve
      key.public_key = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
      signature = Bitcoin::OpenSSL_EC.repack_der_signature(signature)
      if signature
        key.dsa_verify_asn1(hash, signature)
      else
        false
      end
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
      OpenSSL_EC.regenerate_key(private_key)[1]
    end

    def bitcoin_signed_message_hash(message)
      # TODO: this will fail horribly on messages with len > 255. It's a cheap implementation of Bitcoin's CDataStream.
      data = "\x18Bitcoin Signed Message:\n" + [message.bytesize].pack("C") + message
      Digest::SHA256.digest(Digest::SHA256.digest(data))
    end

    def sign_message(private_key_hex, public_key_hex, message)
      hash = bitcoin_signed_message_hash(message)
      signature = OpenSSL_EC.sign_compact(hash, private_key_hex, public_key_hex)
      { 'address' => pubkey_to_address(public_key_hex), 'message' => message, 'signature' => [ signature ].pack("m0") }
    end

    def verify_message(address, signature, message)
      hash = bitcoin_signed_message_hash(message)
      signature = signature.unpack("m0")[0] rescue nil # decode base64
      raise "invalid address"           unless valid_address?(address)
      raise "malformed base64 encoding" unless signature
      raise "malformed signature"       unless signature.bytesize == 65
      pubkey = OpenSSL_EC.recover_compact(hash, signature)
      pubkey_to_address(pubkey) == address if pubkey
    rescue => ex
      p [ex.message, ex.backtrace]; false
    end


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

    # Calculate new difficulty target. Note this takes in details of the preceeding
    # block, not the current one.
    #
    # prev_height is the height of the block before the retarget occurs
    # prev_block_time "time" field from the block before the retarget occurs
    # prev_block_bits "bits" field from the block before the retarget occurs (target as a compact value)
    # last_retarget_time is the "time" field from the block when a retarget last occurred
    def block_new_target(prev_height, prev_block_time, prev_block_bits, last_retarget_time)
      # target interval - what is the ideal interval between the blocks
      retarget_time = Bitcoin.network[:retarget_time]

      actual_time = prev_block_time - last_retarget_time

      min = retarget_time / 4
      max = retarget_time * 4

      actual_time = min if actual_time < min
      actual_time = max if actual_time > max

      # It could be a bit confusing: we are adjusting difficulty of the previous block, while logically
      # we should use difficulty of the previous retarget block

      prev_target = decode_compact_bits(prev_block_bits).to_i(16)

      new_target = prev_target * actual_time / retarget_time
      if new_target < Bitcoin.decode_compact_bits(Bitcoin.network[:proof_of_work_limit]).to_i(16)
        encode_compact_bits(new_target.to_s(16))
      else
        Bitcoin.network[:proof_of_work_limit]
      end
    end

    # average number of hashes required to win a block with the current target. (nbits)
    def block_hashes_to_win(target_nbits)
      current_target  = decode_compact_bits(target_nbits).to_i(16)
      0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff / current_target
    end

    # probability of a single hash solving a block with the current difficulty.
    def block_probability(target_nbits)
      current_target  = decode_compact_bits(target_nbits).to_i(16)
      "%.55f" % (current_target.to_f / 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    end

    # average time to find a block in seconds with the current target. (nbits)
    def block_average_hashing_time(target_nbits, hashes_per_second)
      block_hashes_to_win(target_nbits) / hashes_per_second
    end

    # average mining time (in days) using Mh/s to get btc
    def block_average_mining_time(block_nbits, block_height, mega_hashes_per_second, target_btc=1.0)
      seconds = block_average_hashing_time(block_nbits, mega_hashes_per_second * 1_000_000)
      reward  = block_creation_reward(block_height) / COIN # satoshis to btc
      (days = seconds / 60 / 60 / 24) * (target_btc / reward)
    end

    # shows the total number of Bitcoins in circulation, reward era and reward in that era.
    def blockchain_total_btc(height)
      reward, interval = Bitcoin.network[:reward_base], Bitcoin.network[:reward_halving]
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
      Bitcoin.network[:reward_base] / (2 ** (block_height / Bitcoin.network[:reward_halving].to_f).floor)
    end
  end

  extend Util


  module  BinaryExtensions
    # bin-to-hex
    def bth; unpack("H*")[0]; end
    # hex-to-bin
    def htb; [self].pack("H*"); end

    def htb_reverse; htb.reverse; end
    def hth; unpack("H*")[0]; end
    def reverse_hth; reverse.hth; end
  end

  class ::String
    include Bitcoin::BinaryExtensions
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
      def pubkey_compressed?; public_key.group.point_conversion_form == :compressed; end
    end
    class PKey::EC::Point
      def self.from_hex(group, hex)
        new(group, BN.from_hex(hex))
      end
      def to_hex; to_bn.to_hex; end
      def self.bn2mpi(hex) BN.from_hex(hex).to_mpi; end
      def ec_add(point); self.class.new(group, OpenSSL::BN.from_hex(OpenSSL_EC.ec_add(self, point))); end
    end
  end

  autoload :OpenSSL_EC, "bitcoin/ffi/openssl"

  autoload :Secp256k1, "bitcoin/ffi/secp256k1"
  autoload :BitcoinConsensus, "bitcoin/ffi/bitcoinconsensus"

  @network = :bitcoin

  def self.network
    # Store the copy of network options so we can modify them in tests without breaking the defaults
    @network_options ||= NETWORKS[@network].dup
  end

  def self.network_name
    @network
  end

  def self.network_project
    @network_project
  end

  def self.network=(name)
    raise "Network descriptor '#{name}' not found."  unless NETWORKS[name.to_sym]
    @network_options = nil # clear cached parameters
    @network = name.to_sym
    @network_project = network[:project] rescue nil
    Dogecoin.load  if dogecoin? || dogecoin_testnet?
    Namecoin.load  if namecoin? && defined?(Namecoin)
    @network
  end

  [:bitcoin, :namecoin, :litecoin, :dogecoin, :dogecoin_testnet].each do |n|
    instance_eval "def #{n}?; network_project == :#{n}; end"
  end


  # maximum size of a block (in bytes)
  MAX_BLOCK_SIZE = 1_000_000

  # soft limit for new blocks
  MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2

  # maximum number of signature operations in a block
  MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50

  # maximum number of orphan transactions to be kept in memory
  MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100

  # Threshold for lock_time: below this value it is interpreted as block number, otherwise as UNIX timestamp.
  LOCKTIME_THRESHOLD = 500000000 # Tue Nov  5 00:53:20 1985 UTC

  # maximum integer value
  UINT32_MAX = 0xffffffff
  INT_MAX = 0xffffffff # deprecated name, left here for compatibility with existing users.

  # number of confirmations required before coinbase tx can be spent
  COINBASE_MATURITY = 100

  # interval (in blocks) for difficulty retarget
  RETARGET_INTERVAL = 2016
  RETARGET = 2016 # deprecated constant


  # interval (in blocks) for mining reward reduction
  REWARD_DROP = 210_000

  CENT =   1_000_000
  COIN = 100_000_000

  MIN_FEE_MODE     = [ :block, :relay, :send ]

  NETWORKS = {
    bitcoin: {
      project: :bitcoin,
      magic_head: "\xF9\xBE\xB4\xD9",
      address_version: "00",
      p2sh_version: "05",
      privkey_version: "80",
      default_port: 8333,
      protocol_version: 70001,
      coinbase_maturity: 100,
      reward_base: 50 * COIN,
      reward_halving: 210_000,
      retarget_interval: 2016,
      retarget_time: 1209600, # 2 weeks
      target_spacing: 600, # block interval
      max_money: 21_000_000 * COIN,
      min_tx_fee: 10_000,
      min_relay_tx_fee: 10_000,
      free_tx_bytes: 1_000,
      dust: CENT,
      per_dust_fee: false,
      dns_seeds: [
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org",
      ],
      genesis_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      proof_of_work_limit: 0x1d00ffff,
      alert_pubkeys: ["04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284"],
      known_nodes: [
        'relay.eligius.st',
        'mining.bitcoin.cz',
        'blockchain.info',
        'blockexplorer.com',
      ],
      checkpoints: {
         11111 => "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
         33333 => "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
         74000 => "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
        105000 => "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
        134444 => "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
        168000 => "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
        193000 => "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",
        210000 => "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
        216116 => "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",
        225430 => "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",
        290000 => "0000000000000000fa0b2badd05db0178623ebf8dd081fe7eb874c26e27d0b3b",
        300000 => "000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254",
        305000 => "0000000000000000142bb90561e1a907d500bf534a6727a63a92af5b6abc6160",
      }
    }
  }

  NETWORKS[:testnet] = NETWORKS[:bitcoin].merge({
      magic_head: "\xFA\xBF\xB5\xDA",
      address_version: "6f",
      p2sh_version: "c4",
      privkey_version: "ef",
      default_port: 18333,
      dns_seeds: [ ],
      genesis_hash: "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008",
      proof_of_work_limit: 0x1d07fff8,
      alert_pubkeys: ["04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a"],
      known_nodes: [],
      checkpoints: {},
    })

  NETWORKS[:regtest] = NETWORKS[:testnet].merge({
      default_port: 18444,
      genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
      proof_of_work_limit: (1 << 255) - 1,
    })

  NETWORKS[:testnet3] = NETWORKS[:testnet].merge({
      magic_head: "\x0B\x11\x09\x07",
      no_difficulty: true, # no good. add right testnet3 difficulty calculation instead
      genesis_hash: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
      proof_of_work_limit: 0x1d00ffff,
      dns_seeds: [
        "testnet-seed.alexykot.me",
        "testnet-seed.bitcoin.schildbach.de",
        "testnet-seed.bitcoin.petertodd.org",
        "testnet-seed.bluematt.me",
      ],
      checkpoints: {
        # 542 contains invalid transaction
        542 => "0000000083c1f82cf72c6724f7a317325806384b06408bce7a4327f418dfd5ad",
        71018 => "000000000010dd93dc55541116b2744eb8f4c3b706df6e8512d231a03fb9e435",
        200000 => "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2",
        250000 => "0000000005910c146e4e8d71e8aa6617393738a9794b43cf113076dbaf08460b",
      }
    })

  NETWORKS[:litecoin] = NETWORKS[:bitcoin].merge({
      project: :litecoin,
      magic_head: "\xfb\xc0\xb6\xdb",
      address_version: "30",
      p2sh_version: "05",
      privkey_version: "b0",
      default_port: 9333,
      protocol_version: 70002,
      max_money: 84_000_000 * COIN,
      min_tx_fee: 100_000, # 0.001 LTC
      min_relay_tx_fee: 100_000, # 0.001 LTC
      free_tx_bytes: 5_000,
      dust: CENT / 10,
      per_dust_fee: true,
      reward_halving: 840_000,
      retarget_time: 302400, # 3.5 days
      dns_seeds: [
        "dnsseed.litecointools.com",
        "dnsseed.litecoinpool.org",
        "dnsseed.ltc.xurious.com",
        "dnsseed.koin-project.com",
        "dnsseed.weminemnc.com",
      ],
      genesis_hash: "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
      proof_of_work_limit: 0x1e0fffff,
      alert_pubkeys: ["040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"],
      known_nodes: [],
      checkpoints: {
             1 => "80ca095ed10b02e53d769eb6eaf92cd04e9e0759e5be4a8477b42911ba49c78f",
             2 => "13957807cdd1d02f993909fa59510e318763f99a506c4c426e3b254af09f40d7",
          1500 => "841a2965955dd288cfa707a755d05a54e45f8bd476835ec9af4402a2b59a2967",
          4032 => "9ce90e427198fc0ef05e5905ce3503725b80e26afd35a987965fd7e3d9cf0846",
          8064 => "eb984353fc5190f210651f150c40b8a4bab9eeeff0b729fcb3987da694430d70",
         16128 => "602edf1859b7f9a6af809f1d9b0e6cb66fdc1d4d9dcd7a4bec03e12a1ccd153d",
         23420 => "d80fdf9ca81afd0bd2b2a90ac3a9fe547da58f2530ec874e978fce0b5101b507",
         50000 => "69dc37eb029b68f075a5012dcc0419c127672adb4f3a32882b2b3e71d07a20a6",
         80000 => "4fcb7c02f676a300503f49c764a89955a8f920b46a8cbecb4867182ecdb2e90a",
        120000 => "bd9d26924f05f6daa7f0155f32828ec89e8e29cee9e7121b026a7a3552ac6131",
        161500 => "dbe89880474f4bb4f75c227c77ba1cdc024991123b28b8418dbbf7798471ff43",
        179620 => "2ad9c65c990ac00426d18e446e0fd7be2ffa69e9a7dcb28358a50b2b78b9f709",
        240000 => "7140d1c4b4c2157ca217ee7636f24c9c73db39c4590c4e6eab2e3ea1555088aa",
        383640 => "2b6809f094a9215bafc65eb3f110a35127a34be94b7d0590a096c3f126c6f364",
        409004 => "487518d663d9f1fa08611d9395ad74d982b667fbdc0e77e9cf39b4f1355908a3",
        456000 => "bf34f71cc6366cd487930d06be22f897e34ca6a40501ac7d401be32456372004",
        541794 => "1cbccbe6920e7c258bbce1f26211084efb19764aa3224bec3f4320d77d6a2fd2",
      },
      auxpow_chain_id: 1,
    })

  NETWORKS[:litecoin_testnet] = NETWORKS[:litecoin].merge({
      magic_head: "\xfc\xc1\xb7\xdc",
      address_version: "6f",
      p2sh_version: "c4",
      privkey_version: "ef",
      default_port: 19333,
      dns_seeds: [
        "testnet-seed.litecointools.com",
        "testnet-seed.ltc.xurious.com",
        "testnet-seed.weminemnc.com",
      ],
      genesis_hash: "f5ae71e26c74beacc88382716aced69cddf3dffff24f384e1808905e0188f68f",
      alert_pubkeys: ["04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a"],
      known_nodes: [],
      checkpoints: {
        546 => "a0fea99a6897f531600c8ae53367b126824fd6a847b2b2b73817a95b8e27e602",
      }
    })

  NETWORKS[:dogecoin] = NETWORKS[:litecoin].merge({
      project: :dogecoin,
      magic_head: "\xc0\xc0\xc0\xc0",
      address_version: "1e",
      p2sh_version: "16",
      privkey_version: "9e",
      default_port: 22556,
      protocol_version: 70003,
      max_money: 100_000_000_000 * COIN,
      min_tx_fee: COIN,
      min_relay_tx_fee: COIN,
      free_tx_bytes: 26_000,
      dust: COIN,
      per_dust_fee: true,
      coinbase_maturity: 30,
      coinbase_maturity_new: 240,
      reward_base: 500_000 * COIN,
      reward_halving: 100_000,
      retarget_interval: 240,
      retarget_time: 14400, # 4 hours
      retarget_time_new: 60, # 1 minute
      target_spacing: 60, # block interval
      dns_seeds: [
        "seed.dogechain.info", 
        "seed.dogecoin.com",
      ],
      genesis_hash: "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691",
      proof_of_work_limit: 0x1e0fffff,
      alert_pubkeys: [],
      known_nodes: [
        "daemons.chain.so",
        "bootstrap.chain.so",
      ],
      checkpoints: {
        0 => "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691",
        42279 => "8444c3ef39a46222e87584ef956ad2c9ef401578bd8b51e8e4b9a86ec3134d3a",
        42400 => "557bb7c17ed9e6d4a6f9361cfddf7c1fc0bdc394af7019167442b41f507252b4",
        104679 => "35eb87ae90d44b98898fec8c39577b76cb1eb08e1261cfc10706c8ce9a1d01cf",
        128370 => "3f9265c94cab7dc3bd6a2ad2fb26c8845cb41cff437e0a75ae006997b4974be6",
        145000 => "cc47cae70d7c5c92828d3214a266331dde59087d4a39071fa76ddfff9b7bde72",
        165393 => "7154efb4009e18c1c6a6a79fc6015f48502bcd0a1edd9c20e44cd7cbbe2eeef1",
        186774 => "3c712c49b34a5f34d4b963750d6ba02b73e8a938d2ee415dcda141d89f5cb23a",
        199992 => "3408ff829b7104eebaf61fd2ba2203ef2a43af38b95b353e992ef48f00ebb190",
        225000 => "be148d9c5eab4a33392a6367198796784479720d06bfdd07bd547fe934eea15a",
        250000 => "0e4bcfe8d970979f7e30e2809ab51908d435677998cf759169407824d4f36460",
        270639 => "c587a36dd4f60725b9dd01d99694799bef111fc584d659f6756ab06d2a90d911",
        299742 => "1cc89c0c8a58046bf0222fe131c099852bd9af25a80e07922918ef5fb39d6742",
        323141 => "60c9f919f9b271add6ef5671e9538bad296d79f7fdc6487ba702bf2ba131d31d",
        339202 => "8c29048df5ae9df38a67ea9470fdd404d281a3a5c6f33080cd5bf14aa496ab03"
      },
      auxpow_chain_id: 0x0062,
      # Doge-specific hard-fork cutoffs
      difficulty_change_block: 145000,
      maturity_change_block: 145000,
      auxpow_start_block: 371337
    })

  NETWORKS[:dogecoin_testnet] = NETWORKS[:dogecoin].merge({
      project: :dogecoin,
      magic_head: "\xfc\xc1\xb7\xdc",
      address_version: "71",
      p2sh_version: "c4",
      privkey_version: "f1",
      default_port: 44556,
      protocol_version: 70003,
      min_tx_fee: COIN,
      min_relay_tx_fee: COIN,
      dust: COIN,
      per_dust_fee: true,
      free_tx_bytes: 26_000,
      coinbase_maturity: 30,
      coinbase_maturity_new: 240,
      reward_base: 500_000 * COIN,
      reward_halving: 100_000,
      retarget_interval: 240,
      retarget_time: 14400, # 4 hours
      retarget_time_new: 60, # 1 minute
      target_spacing: 60, # block interval
      max_money: 100_000_000_000 * COIN,
      dns_seeds: [ 
        "testdoge-seed.lionservers.de",
      ],
      genesis_hash: "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e",
      proof_of_work_limit: 0x1e0fffff,
      alert_pubkeys: [],
      known_nodes: [
		    "localhost",
        "testnets.chain.so", 
      ],
      checkpoints: {
        546 => "ac537cfeda975e45040e9938d08e40a16e0fbd6388d02d9b4928b8ae0108c626",
      },
      auxpow_chain_id: 0x0062,
      # Doge-specific hard-fork cutoffs
      difficulty_change_block: 145000,
      maturity_change_block: 145000,
      reset_target_block: 157500,
      auxpow_start_block: 158100
    })

  NETWORKS[:namecoin] = NETWORKS[:bitcoin].merge({
      project: :namecoin,
      magic_head: "\xF9\xBE\xB4\xFE",
      address_version: "34",
      default_port: 8334,
      protocol_version: 35000,
      min_tx_fee: 50_000,
      per_dust_fee: true,
      dns_seeds: [],
      genesis_hash: "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
      known_nodes: [
        "bitcoin.tunl.in",
        "webbtc.com",
        "178.32.31.41",
        "78.47.86.43",
        "69.164.206.88",
      ],
      checkpoints: {
        0 => "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
        19200 => "d8a7c3e01e1e95bcee015e6fcc7583a2ca60b79e5a3aa0a171eddd344ada903d",
        24000 => "425ab0983cf04f43f346a4ca53049d0dc2db952c0a68eb0b55c3bb64108d5371",
        97778 => "7553b1e43da01cfcda4335de1caf623e941d43894bd81c2af27b6582f9d83c6f",
        165000 => "823d7a54ebab04d14c4ba3508f6b5f25977406f4d389539eac0174d52c6b4b62",
      },
      auxpow_chain_id: 1
    })

  NETWORKS[:namecoin_testnet] = NETWORKS[:namecoin].merge({
      magic_head: "\xFA\xBF\xB5\xFE",
      default_port: 18334,
      genesis_hash: "00000001f8ab0d14bceaeb50d163b0bef15aecf62b87bd5f5c864d37f201db97",
      known_nodes: ["178.32.31.41"],
      checkpoints: {
        0 => "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
      }
    })

end
