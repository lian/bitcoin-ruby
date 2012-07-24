# autoload when you need to re-generate a public_key from only its private_key.
# ported from: https://github.com/sipa/bitcoin/blob/2d40fe4da9ea82af4b652b691a4185431d6e47a8/key.h

Bitcoin.require_dependency :ffi, exit: false, message:
  "Skipping FFI needed for OpenSSL_EC.regenerate_key."

module Bitcoin
module OpenSSL_EC
  extend FFI::Library
  ffi_lib 'ssl'

  NID_secp256k1 = 714

  attach_function :SSL_library_init, [], :int
  attach_function :ERR_load_crypto_strings, [], :void
  attach_function :SSL_load_error_strings, [], :void
  attach_function :RAND_poll, [], :int

  #attach_function :BN_bin2bn, [:string, :int, :pointer], :pointer
  attach_function :BN_bin2bn, [:pointer, :int, :pointer], :pointer
  attach_function :EC_KEY_new_by_curve_name, [:int], :pointer
  attach_function :EC_KEY_get0_group, [:pointer], :pointer
  attach_function :BN_new, [], :pointer
  attach_function :BN_CTX_new, [], :pointer
  attach_function :EC_GROUP_get_order, [:pointer, :pointer, :pointer], :int
  attach_function :EC_POINT_new, [:pointer], :pointer
  attach_function :EC_POINT_mul, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :EC_KEY_set_private_key, [:pointer, :pointer], :int
  attach_function :EC_KEY_set_public_key,  [:pointer, :pointer], :int
  attach_function :BN_free, [:pointer], :int
  attach_function :EC_POINT_free, [:pointer], :int
  attach_function :BN_CTX_free, [:pointer], :int
  attach_function :EC_KEY_free, [:pointer], :int
  attach_function :i2o_ECPublicKey, [:pointer, :pointer], :uint
  attach_function :i2d_ECPrivateKey, [:pointer, :pointer], :int
  attach_function :d2i_ECPrivateKey, [:pointer, :pointer, :long], :pointer
  attach_function :EC_KEY_get0_private_key, [:pointer], :pointer
  attach_function :BN_bn2bin, [:pointer, :pointer], :void


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
    ptr = FFI::MemoryPointer.new(:pointer)
    priv_hex = if i2d_ECPrivateKey(eckey, ptr) == length
      size = ptr.read_pointer.get_array_of_uint8(8, 1)[0]
      ptr.read_pointer.get_array_of_uint8(9, size).pack("C*").rjust(32, "\x00").unpack("H*")[0]
      #der_to_private_key( ptr.read_pointer.read_string(length).unpack("H*")[0] )
    end

    if priv_hex != private_key_hex
      raise "regenerated wrong private_key, raise here before generating a faulty public_key too!"
    end


    length = i2o_ECPublicKey(eckey, nil)
    ptr = FFI::MemoryPointer.new(:pointer)
    pub_hex = if i2o_ECPublicKey(eckey, ptr) == length
      ptr.read_pointer.read_string(length).unpack("H*")[0]
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
