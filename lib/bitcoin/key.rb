# encoding: ascii-8bit

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
      compressed = hex.size == 76
      version, key, flag, checksum = hex.unpack("a2a64a#{compressed ? 2 : 0}a8")
      raise "Invalid version"   unless version == Bitcoin.network[:privkey_version]
      raise "Invalid checksum"  unless Bitcoin.checksum(version + key + flag) == checksum
      key = new(key, nil, compressed)
    end

    def == other
      self.priv == other.priv
    end

    # Create a new key with given +privkey+ and +pubkey+.
    #  Bitcoin::Key.new
    #  Bitcoin::Key.new(privkey)
    #  Bitcoin::Key.new(nil, pubkey)
    def initialize privkey = nil, pubkey = nil, compressed = false
      @key = Bitcoin.bitcoin_elliptic_curve
      @pubkey_compressed = pubkey ? self.class.is_compressed_pubkey?(pubkey) : compressed
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
      @pubkey_compressed ? pub_compressed : pub_uncompressed
    end

    def pub_compressed
      regenerate_pubkey unless @key.public_key
      return nil        unless @key.public_key
      @key.public_key.group.point_conversion_form = :compressed
      hex = @key.public_key.to_hex.rjust(66, '0')
      @key.public_key.group.point_conversion_form = :uncompressed
      hex
    end

    def pub_uncompressed
      regenerate_pubkey unless @key.public_key
      return nil        unless @key.public_key
      @key.public_key.group.point_conversion_form = :uncompressed
      @key.public_key.to_hex.rjust(130, '0')
    end

    def compressed
      @pubkey_compressed
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


    def sign_message(message)
      Bitcoin.sign_message(priv, pub, message)['signature']
    end

    def verify_message(signature, message)
      Bitcoin.verify_message(addr, signature, message)
    end

    def self.verify_message(address, signature, message)
      Bitcoin.verify_message(address, signature, message)
    end

    # Thanks to whoever wrote http://pastebin.com/bQtdDzHx
    # for help with compact signatures
    #
    # Given +data+ and a compact signature (65 bytes, base64-encoded to
    # a larger string), recover the public components of the key whose
    # private counterpart validly signed +data+.
    #
    # If the signature validly signed +data+, create a new Key
    # having the signing public key and address. Otherwise return nil.
    #
    # Be sure to check that the returned Key matches the one you were
    # expecting! Otherwise you are merely checking that *someone* validly
    # signed the data.
    def self.recover_compact_signature_to_key(data, signature_base64)
      signature = signature_base64.unpack("m0")[0]
      return nil if signature.size != 65

      version = signature.unpack('C')[0]
      return nil if version < 27 or version > 34
 
      compressed = (version >= 31) ? (version -= 4; true) : false

      hash = Bitcoin.bitcoin_signed_message_hash(data)
      pub_hex = Bitcoin::OpenSSL_EC.recover_public_key_from_signature(hash, signature, version-27, compressed)
      return nil unless pub_hex

      Key.new(nil, pub_hex)
    end

    # Export private key to base58 format.
    # See also Key.from_base58
    def to_base58
      data = Bitcoin.network[:privkey_version] + priv
      data += "01"  if @pubkey_compressed
      hex  = data + Bitcoin.checksum(data)
      Bitcoin.int_to_base58( hex.to_i(16) )
    end

    protected

    # Regenerate public key from the private key.
    def regenerate_pubkey
      return nil unless @key.private_key
      set_pub(Bitcoin::OpenSSL_EC.regenerate_key(priv)[1])
    end

    # Set +priv+ as the new private key (converting from hex).
    def set_priv(priv)
      @key.private_key = OpenSSL::BN.from_hex(priv)
    end

    # Set +pub+ as the new public key (converting from hex).
    def set_pub(pub)
      @pubkey_compressed ||= self.class.is_compressed_pubkey?(pub)
      @key.public_key = OpenSSL::PKey::EC::Point.from_hex(@key.group, pub)
    end

    def self.is_compressed_pubkey?(pub)
      ["02","03"].include?(pub[0..1])
    end

  end

end

