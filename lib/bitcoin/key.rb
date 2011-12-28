module Bitcoin

  # Elliptic Curve key as used in bitcoin.
  class Key

    # Generate a new keypair.
    #  Bitcoin::Key.generate
    def self.generate
      k = new; k.generate; k
    end

    # Import private key from base58 fromat as described in
    # https://en.bitcoin.it/wiki/Private_key#Base_58_Wallet_Import_format and
    # https://en.bitcoin.it/wiki/Base58Check_encoding#Encoding_a_private_key.
    # See also #to_base58
    def self.from_base58(str)
      hex = Bitcoin.base58_to_hex(str)
      version, key, checksum = hex.unpack("a2a64a8")
      raise "Invalid version"  unless version == Bitcoin.network[:privkey_version]
      raise "Invalid checksum"  unless Bitcoin.checksum(version + key) == checksum
      new(key)
    end

    # Create a new key with given +privkey+ and +pubkey+.
    #  Bitcoin::Key.new
    #  Bitcoin::Key.new(privkey)
    #  Bitcoin::Key.new(nil, pubkey)
    def initialize privkey = nil, pubkey = nil
      @key = Bitcoin.bitcoin_elliptic_curve
      set_priv(privkey)  if privkey
      set_pub(pubkey)  if pubkey
    end

    # Generate new priv/pub key.
    def generate
      @key.generate_key
    end

    # Get the private key (in hex).
    def priv
      return nil  unless @key.private_key
      @key.private_key.to_hex.rjust(64, '0')
    end

    # Set the private key to +priv+ (in hex).
    def priv= priv
      set_priv(priv)
    end

    # Get the public key (in hex).
    # In case the key was initialized with only
    # a private key, the public key is regenerated.
    def pub
      unless @key.public_key
        if @key.private_key
          set_pub(Bitcoin::OpenSSL_EC.regenerate_key(priv)[1])
        else
          return nil
        end
      end
      @key.public_key.to_hex.rjust(130, '0')
    end

    # Set the public key (in hex).
    def pub= pub
      set_pub(pub)
    end

    # Get the hash160 of the public key.
    def hash160
      Bitcoin.hash160(pub)
    end

    # Get the address corresponding to the public key.
    def addr
      Bitcoin.hash160_to_address(hash160)
    end

    # Sign +data+ with the key.
    #  key1 = Bitcoin::Key.generate
    #  sig = key.sign("some data")
    def sign(data)
      @key.dsa_sign_asn1(data)
    end

    # Verify signature +sig+ for +data+.
    #  key2 = Bitcoin::Key.new(nil, key1.pub)
    #  key2.verify("some data", sig)
    def verify(data, sig)
      @key.dsa_verify_asn1(data, sig)
    end

    # Export private key to base58 format.
    # See also Key.from_base58
    def to_base58
      data = Bitcoin.network[:privkey_version] + priv
      Bitcoin.encode_base58(data + Bitcoin.checksum(data))
    end

    protected

    # Regenerate public key from the private key.
    def regenerate_pubkey
      set_pub(Bitcoin::OpenSSL_EC.regenerate_key(priv)[1])
    end

    # Set +priv+ as the new private key (converting from hex).
    def set_priv(priv)
      @key.private_key = OpenSSL::BN.from_hex(priv)
    end

    # Set +pub+ as the new public key (converting from hex).
    def set_pub(pub)
      @key.public_key = OpenSSL::PKey::EC::Point.from_hex(@key.group, pub)
    end

  end


  # Deterministic key generator as described in
  # https://bitcointalk.org/index.php?topic=11665.0.
  # 
  # Takes a seed and generates an arbitrary amount of keys.
  # Protects against brute-force attacks by requiring the
  # key hash to fit a difficulty target, much like the block chain.
  class KeyGenerator

    # difficulty target (0x0000FFFF00000000000000000000000000000000000000000000000000000000)
    DEFAULT_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000

    attr_accessor :seed, :nonce, :target

    # Initialize key generator with optional +seed+ and +nonce+ and +target+.
    # [seed] the seed data for the keygenerator (default: random)
    # [nonce] the nonce required to satisfy the target (default: computed)
    # [target] custom difficulty target (default: DEFAULT_TARGET)
    #
    # Example:
    #  g = KeyGenerator.new #=> random seed, computed nonce, default target
    #  KeyGenerator.new(g.seed)
    #  KeyGenerator.new(g.seed, g.nonce)
    #  g.get_key(0) #=> <Bitcoin::Key>
    #
    # Note: When initializing without seed, you should obviously save the
    # seed once it is generated. Saving the nonce is optional; it only saves time.
    def initialize seed = nil, nonce = nil, target = nil
      @seed = seed || OpenSSL::Random.random_bytes(64)
      @target = target || DEFAULT_TARGET
      @nonce = check_nonce(nonce)
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
      n += 1  while !check_target(get_hash(@seed, n))
      n
    end

    protected

    # check the nonce; compute if missing, raise if invalid.
    def check_nonce(nonce)
      return find_nonce  unless nonce
      # check_target(get_hash(@seed, nonce)) ? nonce : find_nonce
      raise ArgumentError, "Nonce invalid."  unless check_target(get_hash(@seed, nonce))
      nonce
    end

    # check if given +hash+ satisfies the difficulty target
    def check_target(hash)
      hash.unpack("H*")[0].to_i(16) < @target
    end

    # compute a single SHA256 hash for +d+.
    def sha256(d); Digest::SHA256.digest(d); end

    # get the hash corresponding to +seed+ and +n+.
    def get_hash(seed, n)
      sha256( sha256(seed) + sha256(n.to_s) )
    end

  end

end

