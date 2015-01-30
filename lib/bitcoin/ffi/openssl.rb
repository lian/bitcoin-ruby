# encoding: ascii-8bit

# autoload when you need to re-generate a public_key from only its private_key.
# ported from: https://github.com/sipa/bitcoin/blob/2d40fe4da9ea82af4b652b691a4185431d6e47a8/key.h

require 'ffi'

module Bitcoin
module OpenSSL_EC
  extend FFI::Library
  if FFI::Platform.windows?
    ffi_lib 'libeay32', 'ssleay32'
  else
    ffi_lib 'ssl'
  end

  NID_secp256k1 = 714
  POINT_CONVERSION_COMPRESSED = 2
  POINT_CONVERSION_UNCOMPRESSED = 4

  attach_function :SSL_library_init, [], :int
  attach_function :ERR_load_crypto_strings, [], :void
  attach_function :SSL_load_error_strings, [], :void
  attach_function :RAND_poll, [], :int

  attach_function :BN_CTX_free, [:pointer], :int
  attach_function :BN_CTX_new, [], :pointer
  attach_function :BN_add, [:pointer, :pointer, :pointer], :int
  attach_function :BN_bin2bn, [:pointer, :int, :pointer], :pointer
  attach_function :BN_bn2bin, [:pointer, :pointer], :int
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
  attach_function :BN_rshift1, [:pointer, :pointer], :int
  attach_function :BN_set_word, [:pointer, :int], :int
  attach_function :BN_sub, [:pointer, :pointer, :pointer], :int
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
  attach_function :EC_KEY_check_key, [:pointer], :uint
  attach_function :ECDSA_do_sign, [:pointer, :uint, :pointer], :pointer
  attach_function :BN_num_bits, [:pointer], :int
  attach_function :ECDSA_SIG_free, [:pointer], :void
  attach_function :EC_POINT_add, [:pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :EC_POINT_point2hex, [:pointer, :pointer, :int, :pointer], :string
  attach_function :EC_POINT_hex2point, [:pointer, :string, :pointer, :pointer], :pointer
  attach_function :ECDSA_SIG_new, [], :pointer
  attach_function :d2i_ECDSA_SIG, [:pointer, :pointer, :long], :pointer
  attach_function :i2d_ECDSA_SIG, [:pointer, :pointer], :int
  attach_function :OPENSSL_free, :CRYPTO_free, [:pointer], :void

  def self.BN_num_bytes(ptr); (BN_num_bits(ptr) + 7) / 8; end


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
  def self.recover_public_key_from_signature(message_hash, signature, rec_id, is_compressed)
    return nil if rec_id < 0 or signature.bytesize != 65
    init_ffi_ssl

    signature = FFI::MemoryPointer.from_string(signature)
    #signature_bn = BN_bin2bn(signature, 65, BN_new())
    r = BN_bin2bn(signature[1], 32, BN_new())
    s = BN_bin2bn(signature[33], 32, BN_new())

    n, i = 0, rec_id / 2
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)

    EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED) if is_compressed

    group = EC_KEY_get0_group(eckey)
    order = BN_new()
    EC_GROUP_get_order(group, order, nil)
    x = BN_dup(order)
    BN_mul_word(x, i)
    BN_add(x, x, r)

    field = BN_new()
    EC_GROUP_get_curve_GFp(group, field, nil, nil, nil)

    if BN_cmp(x, field) >= 0
      [r, s, order, x, field].each{|i| BN_free(i) }
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
    zero, rr, sor, eor = BN_new(), BN_new(), BN_new(), BN_new()
    BN_set_word(zero, 0)
    BN_mod_sub(e, zero, e, order, ctx)
    BN_mod_inverse(rr, r, order, ctx)
    BN_mod_mul(sor, s, rr, order, ctx)
    BN_mod_mul(eor, e, rr, order, ctx)
    EC_POINT_mul(group, big_q, eor, big_r, sor, ctx)
    EC_KEY_set_public_key(eckey, big_q)
    BN_CTX_free(ctx)

    [r, s, order, x, field, e, zero, rr, sor, eor].each{|i| BN_free(i) }
    [big_r, big_q].each{|i| EC_POINT_free(i) }

    length = i2o_ECPublicKey(eckey, nil)
    buf = FFI::MemoryPointer.new(:uint8, length)
    ptr = FFI::MemoryPointer.new(:pointer).put_pointer(0, buf)
    pub_hex = if i2o_ECPublicKey(eckey, ptr) == length
      buf.read_string(length).unpack("H*")[0]
    end

    EC_KEY_free(eckey)

    pub_hex
  end

  # Regenerate a DER-encoded signature such that the S-value complies with the BIP62
  # specification.
  #
  def self.signature_to_low_s(signature)
    init_ffi_ssl

    buf = FFI::MemoryPointer.new(:uint8, 34)
    temp = signature.unpack("C*")
    length_r = temp[3]
    length_s = temp[5+length_r]
    sig = FFI::MemoryPointer.from_string(signature)

    # Calculate the lower s value
    s = BN_bin2bn(sig[6 + length_r], length_s, BN_new())
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
    group, order, halforder, ctx = EC_KEY_get0_group(eckey), BN_new(), BN_new(), BN_CTX_new()

    EC_GROUP_get_order(group, order, ctx)
    BN_rshift1(halforder, order)
    if BN_cmp(s, halforder) > 0
      BN_sub(s, order, s)
    end

    BN_free(halforder)
    BN_free(order)
    BN_CTX_free(ctx)

    length_s = BN_bn2bin(s, buf)
    # p buf.read_string(length_s).unpack("H*")

    # Re-encode the signature in DER format
    sig = [0x30, 0, 0x02, length_r]
    sig.concat(temp.slice(4, length_r))
    sig << 0x02
    sig << length_s
    sig.concat(buf.read_string(length_s).unpack("C*"))
    sig[1] = sig.size - 2

    BN_free(s)
    EC_KEY_free(eckey)

    sig.pack("C*")
  end

  def self.sign_compact(hash, private_key, public_key_hex = nil, pubkey_compressed = nil)
    private_key = [private_key].pack("H*") if private_key.bytesize >= 64
    private_key_hex = private_key.unpack("H*")[0]

    public_key_hex = regenerate_key(private_key_hex).last unless public_key_hex
    pubkey_compressed = (public_key_hex[0..1] == "04" ? false : true) unless pubkey_compressed

    init_ffi_ssl
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
    priv_key = BN_bin2bn(private_key, private_key.bytesize, BN_new())

    group, order, ctx = EC_KEY_get0_group(eckey), BN_new(), BN_CTX_new()
    EC_GROUP_get_order(group, order, ctx)

    pub_key = EC_POINT_new(group)
    EC_POINT_mul(group, pub_key, priv_key, nil, nil, ctx)
    EC_KEY_set_private_key(eckey, priv_key)
    EC_KEY_set_public_key(eckey, pub_key)

    signature = ECDSA_do_sign(hash, hash.bytesize, eckey)

    BN_free(order)
    BN_CTX_free(ctx)
    EC_POINT_free(pub_key)
    BN_free(priv_key)
    EC_KEY_free(eckey)

    buf, rec_id, head = FFI::MemoryPointer.new(:uint8, 32), nil, nil
    r, s = signature.get_array_of_pointer(0, 2).map{|i| BN_bn2bin(i, buf); buf.read_string(BN_num_bytes(i)).rjust(32, "\x00") }

    if signature.get_array_of_pointer(0, 2).all?{|i| BN_num_bits(i) <= 256 }
      4.times{|i|
        head = [ 27 + i + (pubkey_compressed ? 4 : 0) ].pack("C")
        if public_key_hex == recover_public_key_from_signature(hash, [head, r, s].join, i, pubkey_compressed)
          rec_id = i; break
        end
      }
    end

    ECDSA_SIG_free(signature)

    [ head, [r,s] ].join if rec_id
  end

  def self.recover_compact(hash, signature)
    return false if signature.bytesize != 65
    #i = signature.unpack("C")[0] - 27
    #pubkey = recover_public_key_from_signature(hash, signature, (i & ~4), i >= 4)

    version = signature.unpack('C')[0]
    return false if version < 27 or version > 34

    compressed = (version >= 31) ? (version -= 4; true) : false
    pubkey = recover_public_key_from_signature(hash, signature, version-27, compressed)
  end

  # lifted from https://github.com/GemHQ/money-tree
  def self.ec_add(point_0, point_1)
    init_ffi_ssl

    eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
    group = EC_KEY_get0_group(eckey)

    point_0_hex = point_0.to_bn.to_s(16)
    point_0_pt = EC_POINT_hex2point(group, point_0_hex, nil, nil)
    point_1_hex = point_1.to_bn.to_s(16)
    point_1_pt = EC_POINT_hex2point(group, point_1_hex, nil, nil)

    sum_point = EC_POINT_new(group)
    success = EC_POINT_add(group, sum_point, point_0_pt, point_1_pt, nil)
    hex = EC_POINT_point2hex(group, sum_point, POINT_CONVERSION_UNCOMPRESSED, nil)
    EC_KEY_free(eckey)
    EC_POINT_free(sum_point)
    hex
  end

  # repack signature for OpenSSL 1.0.1k handling of DER signatures
  # https://github.com/bitcoin/bitcoin/pull/5634/files
  def self.repack_der_signature(signature)
    init_ffi_ssl

    return false if signature.empty?

    # New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first.
    norm_der = FFI::MemoryPointer.new(:pointer)
    sig_ptr  = FFI::MemoryPointer.new(:pointer).put_pointer(0, FFI::MemoryPointer.from_string(signature))

    norm_sig = d2i_ECDSA_SIG(nil, sig_ptr, signature.bytesize)

    derlen = i2d_ECDSA_SIG(norm_sig, norm_der)
    ECDSA_SIG_free(norm_sig)
    return false if derlen <= 0

    ret = norm_der.read_pointer.read_string(derlen)
    OPENSSL_free(norm_der.read_pointer)

    ret
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
