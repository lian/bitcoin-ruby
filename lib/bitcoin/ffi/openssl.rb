# autoload when you need to re-generate a public_key from its private_key.
# ported from: https://github.com/sipa/bitcoin/blob/2d40fe4da9ea82af4b652b691a4185431d6e47a8/key.h

require 'ffi'

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


  def self.regenerate_key(private_key)
    private_key = [private_key].pack("H*") if private_key.bytesize >= (32*2)

    #private_key = FFI::MemoryPointer.new(:uint8, private_key.bytesize)
    #                .put_bytes(0, private_key, 0, private_key.bytesize)
    private_key = FFI::MemoryPointer.from_string(private_key)
 
    init_ffi_ssl
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
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
      ptr.read_pointer.read_string(length)[9...9+32].unpack("H*")[0]
    end

    length = i2o_ECPublicKey(eckey, nil)
    ptr = FFI::MemoryPointer.new(:pointer)
    pub_hex = if i2o_ECPublicKey(eckey, ptr) == length
      ptr.read_pointer.read_string(length).unpack("H*")[0]
    end

    EC_KEY_free(eckey)

    [ priv_hex, pub_hex ]
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


if $0 == __FILE__

  privkey = ["56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc"].pack("H*")
  pubkey =  ["04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3"].pack("H*")
  p [privkey.bytesize, pubkey.bytesize]
  p [privkey, pubkey].map{|i| i.unpack("H*")[0] }

  p Bitcoin::OpenSSL_EC.regenerate_key(privkey)
  p Bitcoin::OpenSSL_EC.regenerate_key(privkey) == [privkey, pubkey].map{|i| i.unpack("H*")[0] }
  puts

  p [
    ["b51386f8275d49d8d30287d7b1afa805790bdd1fe8b13d22d25928c67ea55d02", "0470305ae5278a22499980286d9c513861d89e7b7317c8b891c554d5c8fdd256b03daa0340be4104f8c84cfa98f0da8f16567fcdd3a00fd993adbbe91695671a56"],
    ["d8ebece51adc5fb99dd6994bcb8fa1221d01576fd76af9134ab36f8d4698b55c", "047503421850d3a6eecb7c9de33b367c4d3f96a34ff257ad0c34e234e29f3672525c6b4353ce6fdc9de3f885fdea798982e2252e610065dbdb62cd8cab1fe45822"],
    ["c95c79fb0cc1fe47b384751df0627be40bbe481ec94eeafeb6dc40e94c40de43", "04b746ca07e718c7ca26d4eeec037492777f48bb5c750e972621698f699f530535c0ffa96dad581102d0471add88e691af85955d1fd42f68506f8092fddfe0c47a"],
    ["5b61f807cc938b0fd3ec8f6006737d0002ceca09f296204138c4459de8a856f6", "0487357bf30c13d47d955666f42f87690cfd18be96cc74cda711da74bf76b08ebc6055aba30680e6288df14bda68c781cbf71eaad096c3639e9724c5e26f3acf54"]
  ].map{|key|
    privkey, pubkey = *key.map{|i| [i].pack("H*") }
    p key
    p Bitcoin::OpenSSL_EC.regenerate_key(privkey)
    Bitcoin::OpenSSL_EC.regenerate_key(privkey) == key
  }.all?

  #puts
  #3.times{ p k=Bitcoin.generate_key; p Bitcoin::OpenSSL_EC.regenerate_key(k.first) }

end
