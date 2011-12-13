module Bitcoin

  # deterministic key generator
  # takes a seed and generates an arbitrary amount of keys
  # protects against brute-force attacks by requiring the
  # key hash to fit a difficulty target, much like the block chain.
  class KeyGenerator

    attr_accessor :seed, :nonce

    # initialize key generator with +seed+ and +nonce+.
    # if no +seed+ is given, random data will be used.
    # if no +nonce+ is given, it will be computed.
    def initialize seed = nil, nonce = nil
      @seed = seed || OpenSSL::Random.random_bytes(64)
      @nonce = nonce || find_nonce
    end

    # get key number +n+ from chain
    def get_key(n = 0)
      key = get_hash(@seed, @nonce)
      (n + 1).times { key = sha256(key) }
      key
      Key.new(key.unpack("H*")[0])
    end

    # find a nonce that leads to the privkey satisfying the target
    def find_nonce
      n = 0
      target = 0x0000FFFF00000000000000000000000000000000000000000000000000000000
#      $stdout.sync = true
      while get_hash(@seed, n).unpack("H*")[0].to_i(16) >= target
        n += 1
#        if n % 100_000 == 0
#          print '.' and $stdout.flush
#        end
      end
      n
    end

    protected
    def sha256(d); Digest::SHA256.digest(d); end

    def get_hash(seed, n)
      sha256( sha256(seed) + sha256(n.to_s) )
    end

  end

  # represents an EC key
  class Key

    # generate a new keypair
    #  Bitcoin::Key.generate
    def self.generate
      k = new; k.generate; k
    end

    # create a new key with given +privkey+ and +pubkey+
    #  Bitcoin::Key.new
    #  Bitcoin::Key.new(privkey)
    #  Bitcoin::Key.new(nil, privkey)
    def initialize privkey = nil, pubkey = nil
      @key = Bitcoin.bitcoin_elliptic_curve
      set_priv(privkey)  if privkey
      set_pub(pubkey)  if pubkey
    end

    # generate new priv/pub key
    def generate
      @key.generate_key
    end

    # get the private key (in hex)
    def priv
      return nil  unless @key.private_key
      @key.private_key.to_hex.rjust(64, '0')
    end

    # set the private key to +priv+ (in hex)
    def priv= priv
      set_priv(priv)
    end

    # get the public key (in hex)
    def pub
      return nil  unless @key.public_key
      @key.public_key.to_hex.rjust(130, '0')
    end

    # set the public key (in hex)
    def pub= pub
      set_pub(pub)
    end

    # get the hash160 of the public key
    def hash160
      Bitcoin.hash160(pub)
    end

    # get the address corresponding to the public key
    def addr
      hash160_to_address(hash160)
    end

    # sign +data+ with the key
    #  key1 = Bitcoin::Key.generate
    #  sig = key.sign("some data")
    def sign(data)
      @key.dsa_sign_asn1(data)
    end

    # verify signature +sig+ for +data+
    #  key2 = Bitcoin::Key.new(nil, key1.pub)
    #  key2.verify("some data", sig)
    def verify(data, sig)
      @key.dsa_verify_asn1(data, sig)
    end

    protected

    def set_priv(priv)
      @key.private_key = OpenSSL::BN.from_hex(priv)
    end

    def set_pub(pub)
      @key.public_key = OpenSSL::PKey::EC::Point.from_hex(@key.group, pub)
    end

    def address_version
      Bitcoin.network[:address_version]
    end

    def hash160_to_address(hex)
      hex = address_version + hex
      addr = Bitcoin.encode_base58(hex + Bitcoin.checksum(hex))
      addr = "1" + addr  if address_version == "00"
      addr
    end

  end

end

