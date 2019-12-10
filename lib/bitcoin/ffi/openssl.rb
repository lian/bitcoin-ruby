# encoding: ascii-8bit

require 'ffi'

module Bitcoin
  # autoload when you need to re-generate a public_key from only its private_key.
  # ported from: https://github.com/sipa/bitcoin/blob/2d40fe4da9ea82af4b652b691a4185431d6e47a8/key.h
  module OpenSSL_EC # rubocop:disable Naming/ClassAndModuleCamelCase
    extend FFI::Library
    if FFI::Platform.windows?
      ffi_lib 'libeay32', 'ssleay32'
    else
      ffi_lib [
        'libssl.so.1.1.0', 'libssl.so.1.1',
        'libssl.so.1.0.0', 'libssl.so.10',
        'ssl'
      ]
    end

    NID_secp256k1 = 714 # rubocop:disable Naming/ConstantName
    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    # OpenSSL 1.1.0 version as a numerical version value as defined in:
    # https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_version.html
    VERSION_1_1_0_NUM = 0x10100000

    # OpenSSL 1.1.0 engine constants, taken from:
    # https://github.com/openssl/openssl/blob/2be8c56a39b0ec2ec5af6ceaf729df154d784a43/include/openssl/crypto.h
    OPENSSL_INIT_ENGINE_RDRAND = 0x00000200
    OPENSSL_INIT_ENGINE_DYNAMIC = 0x00000400
    OPENSSL_INIT_ENGINE_CRYPTODEV = 0x00001000
    OPENSSL_INIT_ENGINE_CAPI = 0x00002000
    OPENSSL_INIT_ENGINE_PADLOCK = 0x00004000
    OPENSSL_INIT_ENGINE_ALL_BUILTIN = (
      OPENSSL_INIT_ENGINE_RDRAND |
      OPENSSL_INIT_ENGINE_DYNAMIC |
      OPENSSL_INIT_ENGINE_CRYPTODEV |
      OPENSSL_INIT_ENGINE_CAPI |
      OPENSSL_INIT_ENGINE_PADLOCK
    )

    # OpenSSL 1.1.0 load strings constant, taken from:
    # https://github.com/openssl/openssl/blob/c162c126be342b8cd97996346598ecf7db56130f/include/openssl/ssl.h
    OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000

    # This is the very first function we need to use to determine what version
    # of OpenSSL we are interacting with.
    begin
      attach_function :OpenSSL_version_num, [], :ulong
    rescue FFI::NotFoundError
      attach_function :SSLeay, [], :long
    end

    # Returns the version of SSL present.
    #
    # @return [Integer] version number as an integer.
    def self.version
      if self.respond_to?(:OpenSSL_version_num)
        OpenSSL_version_num()
      else
        SSLeay()
      end
    end

    if version >= VERSION_1_1_0_NUM
      # Initialization procedure for the library was changed in OpenSSL 1.1.0
      attach_function :OPENSSL_init_ssl, [:uint64, :pointer], :int
    else
      attach_function :SSL_library_init, [], :int
      attach_function :ERR_load_crypto_strings, [], :void
      attach_function :SSL_load_error_strings, [], :void
    end

    attach_function :RAND_poll, [], :int

    attach_function :BN_CTX_free, [:pointer], :int
    attach_function :BN_CTX_new, [], :pointer
    attach_function :BN_add, %i[pointer pointer pointer], :int
    attach_function :BN_bin2bn, %i[pointer int pointer], :pointer
    attach_function :BN_bn2bin, %i[pointer pointer], :int
    attach_function :BN_cmp, %i[pointer pointer], :int
    attach_function :BN_dup, [:pointer], :pointer
    attach_function :BN_free, [:pointer], :int
    attach_function :BN_mod_inverse, %i[pointer pointer pointer pointer], :pointer
    attach_function :BN_mod_mul, %i[pointer pointer pointer pointer pointer], :int
    attach_function :BN_mod_sub, %i[pointer pointer pointer pointer pointer], :int
    attach_function :BN_mul_word, %i[pointer int], :int
    attach_function :BN_new, [], :pointer
    attach_function :BN_rshift, %i[pointer pointer int], :int
    attach_function :BN_rshift1, %i[pointer pointer], :int
    attach_function :BN_set_word, %i[pointer int], :int
    attach_function :BN_sub, %i[pointer pointer pointer], :int
    attach_function :EC_GROUP_get_curve_GFp, %i[pointer pointer pointer pointer pointer], :int
    attach_function :EC_GROUP_get_degree, [:pointer], :int
    attach_function :EC_GROUP_get_order, %i[pointer pointer pointer], :int
    attach_function :EC_KEY_free, [:pointer], :int
    attach_function :EC_KEY_get0_group, [:pointer], :pointer
    attach_function :EC_KEY_get0_private_key, [:pointer], :pointer
    attach_function :EC_KEY_new_by_curve_name, [:int], :pointer
    attach_function :EC_KEY_set_conv_form, %i[pointer int], :void
    attach_function :EC_KEY_set_private_key, %i[pointer pointer], :int
    attach_function :EC_KEY_set_public_key,  %i[pointer pointer], :int
    attach_function :EC_POINT_free, [:pointer], :int
    attach_function :EC_POINT_mul, %i[pointer pointer pointer pointer pointer pointer], :int
    attach_function :EC_POINT_new, [:pointer], :pointer
    attach_function :EC_POINT_set_compressed_coordinates_GFp,
                    %i[pointer pointer pointer int pointer], :int
    attach_function :i2o_ECPublicKey, %i[pointer pointer], :uint
    attach_function :ECDSA_do_sign, %i[pointer uint pointer], :pointer
    attach_function :BN_num_bits, [:pointer], :int
    attach_function :ECDSA_SIG_free, [:pointer], :void
    attach_function :EC_POINT_add, %i[pointer pointer pointer pointer pointer], :int
    attach_function :EC_POINT_point2hex, %i[pointer pointer int pointer], :string
    attach_function :EC_POINT_hex2point, %i[pointer string pointer pointer], :pointer
    attach_function :d2i_ECDSA_SIG, %i[pointer pointer long], :pointer
    attach_function :i2d_ECDSA_SIG, %i[pointer pointer], :int
    attach_function :OPENSSL_free, :CRYPTO_free, [:pointer], :void

    def self.BN_num_bytes(ptr) # rubocop:disable Naming/MethodName
      (BN_num_bits(ptr) + 7) / 8
    end

    # resolve public from private key, using ffi and libssl.so
    # example:
    #   keypair = Bitcoin.generate_key; Bitcoin::OpenSSL_EC.regenerate_key(keypair.first) == keypair
    def self.regenerate_key(private_key)
      private_key = [private_key].pack('H*') if private_key.bytesize >= (32 * 2)
      private_key_hex = private_key.unpack('H*')[0]

      group = OpenSSL::PKey::EC::Group.new('secp256k1')
      key = OpenSSL::PKey::EC.new(group)
      key.private_key = OpenSSL::BN.new(private_key_hex, 16)
      key.public_key = group.generator.mul(key.private_key)

      priv_hex = key.private_key.to_bn.to_s(16).downcase.rjust(64, '0')
      if priv_hex != private_key_hex
        raise 'regenerated wrong private_key, raise here before generating a faulty public_key too!'
      end

      [priv_hex, key.public_key.to_bn.to_s(16).downcase]
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
      return nil if rec_id < 0 || signature.bytesize != 65
      init_ffi_ssl

      signature = FFI::MemoryPointer.from_string(signature)
      # signature_bn = BN_bin2bn(signature, 65, BN_new())
      r = BN_bin2bn(signature[1], 32, BN_new())
      s = BN_bin2bn(signature[33], 32, BN_new())

      i = rec_id / 2
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
        [r, s, order, x, field].each { |item| BN_free(item) }
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
      rr = BN_new()
      sor = BN_new()
      eor = BN_new()
      BN_set_word(zero, 0)
      BN_mod_sub(e, zero, e, order, ctx)
      BN_mod_inverse(rr, r, order, ctx)
      BN_mod_mul(sor, s, rr, order, ctx)
      BN_mod_mul(eor, e, rr, order, ctx)
      EC_POINT_mul(group, big_q, eor, big_r, sor, ctx)
      EC_KEY_set_public_key(eckey, big_q)
      BN_CTX_free(ctx)

      [r, s, order, x, field, e, zero, rr, sor, eor].each { |item| BN_free(item) }
      [big_r, big_q].each { |item| EC_POINT_free(item) }

      length = i2o_ECPublicKey(eckey, nil)
      buf = FFI::MemoryPointer.new(:uint8, length)
      ptr = FFI::MemoryPointer.new(:pointer).put_pointer(0, buf)
      pub_hex = buf.read_string(length).unpack('H*')[0] if i2o_ECPublicKey(eckey, ptr) == length

      EC_KEY_free(eckey)

      pub_hex
    end

    # Regenerate a DER-encoded signature such that the S-value complies with the BIP62
    # specification.
    #
    def self.signature_to_low_s(signature)
      init_ffi_ssl

      buf = FFI::MemoryPointer.new(:uint8, 34)
      temp = signature.unpack('C*')
      length_r = temp[3]
      length_s = temp[5 + length_r]
      sig = FFI::MemoryPointer.from_string(signature)

      # Calculate the lower s value
      s = BN_bin2bn(sig[6 + length_r], length_s, BN_new())
      eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
      group = EC_KEY_get0_group(eckey)
      order = BN_new()
      halforder = BN_new()
      ctx = BN_CTX_new()

      EC_GROUP_get_order(group, order, ctx)
      BN_rshift1(halforder, order)
      BN_sub(s, order, s) if BN_cmp(s, halforder) > 0

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
      sig.concat(buf.read_string(length_s).unpack('C*'))
      sig[1] = sig.size - 2

      BN_free(s)
      EC_KEY_free(eckey)

      sig.pack('C*')
    end

    def self.sign_compact(hash, private_key, public_key_hex = nil, pubkey_compressed = nil)
      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hash)

      private_key = [private_key].pack('H*') if private_key.bytesize >= 64
      private_key_hex = private_key.unpack('H*')[0]

      public_key_hex ||= regenerate_key(private_key_hex).last
      pubkey_compressed ||= public_key_hex[0..1] != '04'

      init_ffi_ssl
      eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
      priv_key = BN_bin2bn(private_key, private_key.bytesize, BN_new())

      group = EC_KEY_get0_group(eckey)
      order = BN_new()
      ctx = BN_CTX_new()
      EC_GROUP_get_order(group, order, ctx)

      pub_key = EC_POINT_new(group)
      EC_POINT_mul(group, pub_key, priv_key, nil, nil, ctx)
      EC_KEY_set_private_key(eckey, priv_key)
      EC_KEY_set_public_key(eckey, pub_key)

      signature = ECDSA_do_sign(msg32, msg32.size, eckey)

      BN_free(order)
      BN_CTX_free(ctx)
      EC_POINT_free(pub_key)
      BN_free(priv_key)
      EC_KEY_free(eckey)

      buf = FFI::MemoryPointer.new(:uint8, 32)
      head = nil
      r, s = signature.get_array_of_pointer(0, 2).map do |i|
        BN_bn2bin(i, buf)
        buf.read_string(BN_num_bytes(i)).rjust(32, "\x00")
      end

      rec_id = nil
      if signature.get_array_of_pointer(0, 2).all? { |i| BN_num_bits(i) <= 256 }
        4.times do |i|
          head = [27 + i + (pubkey_compressed ? 4 : 0)].pack('C')
          recovered_key = recover_public_key_from_signature(
            msg32.read_string(32), [head, r, s].join, i, pubkey_compressed
          )
          if public_key_hex == recovered_key
            rec_id = i
            break
          end
        end
      end

      ECDSA_SIG_free(signature)

      [head, [r, s]].join if rec_id
    end

    def self.recover_compact(hash, signature)
      return false if signature.bytesize != 65
      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hash)

      version = signature.unpack('C')[0]
      return false if version < 27 || version > 34

      compressed = version >= 31
      version -= 4 if compressed

      recover_public_key_from_signature(msg32.read_string(32), signature, version - 27, compressed)
    end

    # lifted from https://github.com/GemHQ/money-tree
    def self.ec_add(point0, point1)
      init_ffi_ssl

      eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
      group = EC_KEY_get0_group(eckey)

      point_0_hex = point0.to_bn.to_s(16)
      point_0_pt = EC_POINT_hex2point(group, point_0_hex, nil, nil)
      point_1_hex = point1.to_bn.to_s(16)
      point_1_pt = EC_POINT_hex2point(group, point_1_hex, nil, nil)

      sum_point = EC_POINT_new(group)
      EC_POINT_add(group, sum_point, point_0_pt, point_1_pt, nil)
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
      sig_ptr  = FFI::MemoryPointer.new(:pointer).put_pointer(
        0, FFI::MemoryPointer.from_string(signature)
      )

      norm_sig = d2i_ECDSA_SIG(nil, sig_ptr, signature.bytesize)

      derlen = i2d_ECDSA_SIG(norm_sig, norm_der)
      ECDSA_SIG_free(norm_sig)
      return false if derlen <= 0

      ret = norm_der.read_pointer.read_string(derlen)
      OPENSSL_free(norm_der.read_pointer)

      ret
    end

    def self.init_ffi_ssl
      @ssl_loaded ||= false
      return if @ssl_loaded

      if version >= VERSION_1_1_0_NUM
        OPENSSL_init_ssl(
          OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_ENGINE_ALL_BUILTIN,
          nil
        )
      else
        SSL_library_init()
        ERR_load_crypto_strings()
        SSL_load_error_strings()
      end

      RAND_poll()
      @ssl_loaded = true
    end
  end
end
