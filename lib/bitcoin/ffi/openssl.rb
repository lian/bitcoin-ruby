# autoload when you need to re-generate a public_key from only its private_key.
# ported from: https://github.com/sipa/bitcoin/blob/2d40fe4da9ea82af4b652b691a4185431d6e47a8/key.h

Bitcoin.require_dependency :ffi, exit: false, message:
  "Skipping FFI needed for OpenSSL_EC.regenerate_key."

module Bitcoin
module OpenSSL_EC
  extend FFI::Library
  ffi_lib 'ssl'

  NID_secp256k1 = 714
  POINT_CONVERSION_COMPRESSED = 2

  attach_function :SSL_library_init, [], :int
  attach_function :ERR_load_crypto_strings, [], :void
  attach_function :SSL_load_error_strings, [], :void
  attach_function :RAND_poll, [], :int

  #attach_function :BN_bin2bn, [:string, :int, :pointer], :pointer
  attach_function :BN_CTX_free, [:pointer], :int
  attach_function :BN_CTX_new, [], :pointer
  attach_function :BN_add, [:pointer, :pointer, :pointer], :int
  attach_function :BN_bin2bn, [:pointer, :int, :pointer], :pointer
  attach_function :BN_bn2bin, [:pointer, :pointer], :void
  attach_function :BN_cmp, [:pointer, :pointer], :int
  attach_function :BN_copy, [:pointer, :pointer], :pointer
  attach_function :BN_dup, [:pointer], :pointer
  attach_function :BN_free, [:pointer], :int
  attach_function :BN_mod_inverse, [:pointer, :pointer, :pointer, :pointer], :pointer
  attach_function :BN_mod_mul, [:pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :BN_mod_sub, [:pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :BN_mul_word, [:pointer, :int], :int
  attach_function :BN_new, [], :pointer
  attach_function :BN_rshift, [:pointer, :pointer, :int], :int
  attach_function :BN_set_word, [:pointer, :int], :int
  attach_function :EC_GROUP_get_curve_GFp, [:pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :EC_GROUP_get_degree, [:pointer], :int
  attach_function :EC_GROUP_get_order, [:pointer, :pointer, :pointer], :int
  attach_function :EC_KEY_free, [:pointer], :int
  attach_function :EC_KEY_get0_group, [:pointer], :pointer
  attach_function :EC_KEY_get0_private_key, [:pointer], :pointer
  attach_function :EC_KEY_new_by_curve_name, [:int], :pointer
  attach_function :EC_KEY_set_conv_form, [:pointer, :int], :void
  attach_function :EC_KEY_set_private_key, [:pointer, :pointer], :int
  attach_function :EC_KEY_set_public_key,  [:pointer, :pointer], :int
  attach_function :EC_POINT_free, [:pointer], :int
  attach_function :EC_POINT_is_at_infinity, [:pointer, :pointer], :int
  attach_function :EC_POINT_mul, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :EC_POINT_new, [:pointer], :pointer
  attach_function :EC_POINT_set_compressed_coordinates_GFp, [:pointer, :pointer, :pointer, :int, :pointer], :int
  attach_function :d2i_ECPrivateKey, [:pointer, :pointer, :long], :pointer
  attach_function :i2d_ECPrivateKey, [:pointer, :pointer], :int
  attach_function :i2o_ECPublicKey, [:pointer, :pointer], :uint


  # resolve public from private key, using ffi and libssl.so
  # example:
  #   keypair = Bitcoin.generate_key; Bitcoin::OpenSSL_EC.regenerate_key(keypair.first) == keypair
  def self.regenerate_key(private_key)
    private_key = [private_key].pack("H*") if private_key.bytesize >= (32*2)
    private_key_hex = private_key.unpack("H*")[0]

    #private_key = FFI::MemoryPointer.new(:uint8, private_key.bytesize)
    #                .put_bytes(0, private_key, 0, private_key.bytesize)
    private_key = FFI::MemoryPointer.from_string(private_key)

    init_ffi_ssl
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
    #priv_key = BN_bin2bn(private_key, private_key.size, BN_new())
    priv_key = BN_bin2bn(private_key, private_key.size-1, BN_new())

    group, order, ctx = EC_KEY_get0_group(eckey), BN_new(), BN_CTX_new()
    EC_GROUP_get_order(group, order, ctx)

    pub_key = EC_POINT_new(group)
    EC_POINT_mul(group, pub_key, priv_key, nil, nil, ctx)
    EC_KEY_set_private_key(eckey, priv_key)
    EC_KEY_set_public_key(eckey, pub_key)

    BN_free(order)
    BN_CTX_free(ctx)
    EC_POINT_free(pub_key)
    BN_free(priv_key)


    length = i2d_ECPrivateKey(eckey, nil)
    buf = FFI::MemoryPointer.new(:uint8, length)
    ptr = FFI::MemoryPointer.new(:pointer).put_pointer(0, buf)
    priv_hex = if i2d_ECPrivateKey(eckey, ptr) == length
      size = buf.get_array_of_uint8(8, 1)[0]
      buf.get_array_of_uint8(9, size).pack("C*").rjust(32, "\x00").unpack("H*")[0]
      #der_to_private_key( ptr.read_pointer.read_string(length).unpack("H*")[0] )
    end

    if priv_hex != private_key_hex
      raise "regenerated wrong private_key, raise here before generating a faulty public_key too!"
    end


    length = i2o_ECPublicKey(eckey, nil)
    buf = FFI::MemoryPointer.new(:uint8, length)
    ptr = FFI::MemoryPointer.new(:pointer).put_pointer(0, buf)
    pub_hex = if i2o_ECPublicKey(eckey, ptr) == length
      buf.read_string(length).unpack("H*")[0]
    end

    EC_KEY_free(eckey)

    [ priv_hex, pub_hex ]
  end

  # extract private key from uncompressed DER format
  def self.der_to_private_key(der_hex)
    init_ffi_ssl
    #k  = EC_KEY_new_by_curve_name(NID_secp256k1)
    #kp = FFI::MemoryPointer.new(:pointer).put_pointer(0, eckey)

    buf = FFI::MemoryPointer.from_string([der_hex].pack("H*"))
    ptr = FFI::MemoryPointer.new(:pointer).put_pointer(0, buf)

    #ec_key = d2i_ECPrivateKey(kp, ptr, buf.size-1)
    ec_key = d2i_ECPrivateKey(nil, ptr, buf.size-1)
    return nil if ec_key.null?
    bn = EC_KEY_get0_private_key(ec_key)
    BN_bn2bin(bn, buf)
    buf.read_string(32).unpack("H*")[0]
  end

  # Given the components of a signature and a selector value, recover and
  # return the public key that generated the signature according to the
  # algorithm in SEC1v2 section 4.1.6.
  #
  # rec_id is an index from 0 to 3 that indicates which of the 4 possible
  # keys is the correct one. Because the key recovery operation yields
  # multiple potential keys, the correct key must either be stored alongside
  # the signature, or you must be willing to try each rec_id in turn until
  # you find one that outputs the key you are expecting.
  #
  # If this method returns nil, it means recovery was not possible and rec_id
  # should be iterated.
  #
  # Given the above two points, a correct usage of this method is inside a
  # for loop from 0 to 3, and if the output is nil OR a key that is not the
  # one you expect, you try again with the next rec_id.
  #
  #   message_hash = hash of the signed message.
  #   signature = the R and S components of the signature, wrapped.
  #   rec_id = which possible key to recover.
  #   is_compressed = whether or not the original pubkey was compressed.
  def self.recover_public_key_from_signature(message_hash, signature, rec_id,
    is_compressed)
    return nil if rec_id < 0
    return nil if signature.bytesize != 65
    init_ffi_ssl

    # TODO: does this need to be freed?
    signature = FFI::MemoryPointer.from_string(signature)
    signature_bn = BN_bin2bn(signature, 65, BN_new())
    r = BN_bin2bn(signature[1], 32, BN_new())
    s = BN_bin2bn(signature[33], 32, BN_new())

    n = 0
    i = rec_id / 2
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)

    if is_compressed
      EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED)
    end

    group = EC_KEY_get0_group(eckey)
    order = BN_new()
    EC_GROUP_get_order(group, order, nil)
    x = BN_dup(order)
    BN_mul_word(x, i)
    BN_add(x, x, r)

    field = BN_new()
    EC_GROUP_get_curve_GFp(group, field, nil, nil, nil)

    if BN_cmp(x, field) >= 0
      EC_KEY_free(eckey)
      return nil
    end

    big_r = EC_POINT_new(group)
    EC_POINT_set_compressed_coordinates_GFp(group, big_r, x, rec_id % 2, nil)

    big_q = EC_POINT_new(group)
    n = EC_GROUP_get_degree(group)
    e = BN_bin2bn(message_hash, message_hash.bytesize, BN_new())
    BN_rshift(e, e, 8 - (n & 7)) if 8 * message_hash.bytesize > n

    ctx = BN_CTX_new()
    zero = BN_new()
    BN_set_word(zero, 0)
    BN_mod_sub(e, zero, e, order, ctx)
    rr = BN_new()
    BN_mod_inverse(rr, r, order, ctx)
    sor = BN_new()
    BN_mod_mul(sor, s, rr, order, ctx)
    eor = BN_new()
    BN_mod_mul(eor, e, rr, order, ctx)
    EC_POINT_mul(group, big_q, eor, big_r, sor, ctx)
    EC_KEY_set_public_key(eckey, big_q)
    BN_CTX_free(ctx)

    length = i2o_ECPublicKey(eckey, nil)
    buf = FFI::MemoryPointer.new(:uint8, length)
    ptr = FFI::MemoryPointer.new(:pointer).put_pointer(0, buf)
    pub_hex = if i2o_ECPublicKey(eckey, ptr) == length
      buf.read_string(length).unpack("H*")[0]
    end

    EC_KEY_free(eckey)

    pub_hex
  end

  def self.init_ffi_ssl
    return if @ssl_loaded
    SSL_library_init()
    ERR_load_crypto_strings()
    SSL_load_error_strings()
    RAND_poll()
    @ssl_loaded = true
  end
end
end
