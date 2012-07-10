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
      hex = Bitcoin.decode_base58(str)
      version, key, checksum = hex.unpack("a2a64a8")
      raise "Invalid version"   unless version == Bitcoin.network[:privkey_version]
      raise "Invalid checksum"  unless Bitcoin.checksum(version + key) == checksum
      new(key)
    end

    def == other
      self.priv == other.priv
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
      hex  = data + Bitcoin.checksum(data)
      Bitcoin.int_to_base58( hex.to_i(16) )
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

end

