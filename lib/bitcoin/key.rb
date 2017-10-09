# encoding: ascii-8bit

module Bitcoin

  # Elliptic Curve key as used in bitcoin.
  class Key

    attr_reader :key

    MIN_PRIV_KEY_MOD_ORDER = 0x01
    # Order of secp256k1's generator minus 1.
    MAX_PRIV_KEY_MOD_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140

    # Generate a new keypair.
    #  Bitcoin::Key.generate
    def self.generate(opts={compressed: true})
      k = new(nil, nil, opts); k.generate; k
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

    def ==(other)
      self.priv == other.priv
    end

    # Create a new key with given +privkey+ and +pubkey+.
    #  Bitcoin::Key.new
    #  Bitcoin::Key.new(privkey)
    #  Bitcoin::Key.new(nil, pubkey)
    def initialize(privkey = nil, pubkey = nil, opts={compressed: true})
      compressed = opts.is_a?(Hash) ? opts.fetch(:compressed, true) : opts
      @key = Bitcoin.bitcoin_elliptic_curve
      @pubkey_compressed = pubkey ? self.class.is_compressed_pubkey?(pubkey) : compressed
      set_priv(privkey)  if privkey
      set_pub(pubkey, @pubkey_compressed)  if pubkey
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
      regenerate_pubkey
    end

    # Get the public key (in hex).
    # In case the key was initialized with only
    # a private key, the public key is regenerated.
    def pub
      regenerate_pubkey unless @key.public_key
      return nil        unless @key.public_key
      @pubkey_compressed ? pub_compressed : pub_uncompressed
    end

    def pub_compressed
      public_key = @key.public_key
      public_key.group.point_conversion_form = :compressed
      public_key.to_hex.rjust(66, '0')
    end

    def pub_uncompressed
      public_key = @key.public_key
      public_key.group.point_conversion_form = :uncompressed
      public_key.to_hex.rjust(130, '0')
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
    #  sig = key1.sign("some data")
    def sign(data)
      Bitcoin.sign_data(key, data)
    end

    # Verify signature +sig+ for +data+.
    #  key2 = Bitcoin::Key.new(nil, key1.pub)
    #  key2.verify("some data", sig)
    def verify(data, sig)
      regenerate_pubkey unless @key.public_key
      sig = Bitcoin::OpenSSL_EC.repack_der_signature(sig)
      if sig
        @key.dsa_verify_asn1(data, sig)
      else
        false
      end
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


    # Export private key to bip38 (non-ec-multiply) format as described in
    # https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
    # See also Key.from_bip38
    def to_bip38(passphrase)
      flagbyte = compressed ? "\xe0" : "\xc0"
      addresshash = Digest::SHA256.digest( Digest::SHA256.digest( self.addr ) )[0...4]

      require 'scrypt' unless defined?(::SCrypt::Engine)
      buf = SCrypt::Engine.__sc_crypt(passphrase, addresshash, 16384, 8, 8, 64)
      derivedhalf1, derivedhalf2 = buf[0...32], buf[32..-1]

      aes = proc{|k,a,b|
        cipher = OpenSSL::Cipher::AES.new(256, :ECB); cipher.encrypt; cipher.padding = 0; cipher.key = k
        cipher.update [ (a.to_i(16) ^ b.unpack("H*")[0].to_i(16)).to_s(16).rjust(32, '0') ].pack("H*")
      }

      encryptedhalf1 = aes.call(derivedhalf2, self.priv[0...32], derivedhalf1[0...16])
      encryptedhalf2 = aes.call(derivedhalf2, self.priv[32..-1], derivedhalf1[16..-1])

      encrypted_privkey = "\x01\x42" + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2
      encrypted_privkey += Digest::SHA256.digest( Digest::SHA256.digest( encrypted_privkey ) )[0...4]

      encrypted_privkey = Bitcoin.encode_base58( encrypted_privkey.unpack("H*")[0] )
    end

    # Import private key from bip38 (non-ec-multiply) fromat as described in
    # https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
    # See also #to_bip38
    def self.from_bip38(encrypted_privkey, passphrase)
      version, flagbyte, addresshash, encryptedhalf1, encryptedhalf2, checksum =
        [ Bitcoin.decode_base58(encrypted_privkey) ].pack("H*").unpack("a2aa4a16a16a4")
      compressed = (flagbyte == "\xe0") ? true : false

      raise "Invalid version"   unless version == "\x01\x42"
      raise "Invalid checksum"  unless Digest::SHA256.digest(Digest::SHA256.digest(version + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2))[0...4] == checksum

      require 'scrypt' unless defined?(::SCrypt::Engine)
      buf = SCrypt::Engine.__sc_crypt(passphrase, addresshash, 16384, 8, 8, 64)
      derivedhalf1, derivedhalf2 = buf[0...32], buf[32..-1]

      aes = proc{|k,a|
        cipher = OpenSSL::Cipher::AES.new(256, :ECB); cipher.decrypt; cipher.padding = 0; cipher.key = k
        cipher.update(a)
      }

      decryptedhalf2 = aes.call(derivedhalf2, encryptedhalf2)
      decryptedhalf1 = aes.call(derivedhalf2, encryptedhalf1)

      priv = decryptedhalf1 + decryptedhalf2
      priv = (priv.unpack("H*")[0].to_i(16) ^ derivedhalf1.unpack("H*")[0].to_i(16)).to_s(16).rjust(64, '0')
      key = Bitcoin::Key.new(priv, nil, compressed)

      if Digest::SHA256.digest( Digest::SHA256.digest( key.addr ) )[0...4] != addresshash
        raise "Invalid addresshash! Password is likely incorrect."
      end

      key
    end

    # Import private key from warp fromat as described in
    # https://github.com/keybase/warpwallet
    # https://keybase.io/warp/
    def self.from_warp(passphrase, salt="", compressed=false)
      require 'scrypt' unless defined?(::SCrypt::Engine)
      s1 = SCrypt::Engine.scrypt(passphrase+"\x01", salt+"\x01", 2**18, 8, 1, 32)
      s2 = OpenSSL::PKCS5.pbkdf2_hmac(passphrase+"\x02", salt+"\x02", 2**16, 32, OpenSSL::Digest::SHA256.new)
      s3 = s1.bytes.zip(s2.bytes).map{|a,b| a ^ b }.pack("C*")

      key = Bitcoin::Key.new(s3.unpack("H*")[0], nil, compressed)
      # [key.addr, key.to_base58, [s1,s2,s3].map{|i| i.unpack("H*")[0] }, compressed]
      key
    end


    protected

    # Regenerate public key from the private key.
    def regenerate_pubkey
      return nil unless @key.private_key
      set_pub(Bitcoin::OpenSSL_EC.regenerate_key(priv)[1], @pubkey_compressed)
    end

    # Set +priv+ as the new private key (converting from hex).
    def set_priv(priv)
      value = priv.to_i(16)
      raise 'private key is not on curve' unless MIN_PRIV_KEY_MOD_ORDER <= value && value <= MAX_PRIV_KEY_MOD_ORDER
      @key.private_key = OpenSSL::BN.from_hex(priv)
    end

    # Set +pub+ as the new public key (converting from hex).
    def set_pub(pub, compressed = nil)
      @pubkey_compressed = compressed == nil ? self.class.is_compressed_pubkey?(pub) : compressed
      @key.public_key = OpenSSL::PKey::EC::Point.from_hex(@key.group, pub)
    end

    def self.is_compressed_pubkey?(pub)
      ["02","03"].include?(pub[0..1])
    end

  end

end

