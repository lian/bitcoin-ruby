# encoding: ascii-8bit

# bindings for secp256k1 inside bitcoin (https://github.com/bitcoin/bitcoin/tree/v0.11.0/src/secp256k1)
# tag: v0.11.0
# commit: d26f951802c762de04fb68e1a112d611929920ba

require 'ffi'

module Bitcoin
  module Secp256k1
    extend FFI::Library

    SECP256K1_START_VERIFY = (1 << 0)
    SECP256K1_START_SIGN   = (1 << 1)

    def self.ffi_load_functions(file)
      class_eval <<-RUBY
        ffi_lib [ %[#{file}] ]

        ##
        # source: https://github.com/bitcoin/bitcoin/blob/v0.11.0/src/secp256k1/include/secp256k1.h
        ##

        # secp256k1_context_t* secp256k1_context_create(int flags)
        attach_function :secp256k1_context_create, [:int], :pointer

        # secp256k1_context_t* secp256k1_context_clone(const secp256k1_context_t* ctx)
        attach_function :secp256k1_context_clone, [:pointer], :pointer

        # void secp256k1_context_destroy(secp256k1_context_t* ctx)
        attach_function :secp256k1_context_destroy, [:pointer], :void

        # int secp256k1_ecdsa_verify(const secp256k1_context_t* ctx, const unsigned char *msg32, const unsigned char *sig, int siglen, const unsigned char *pubkey, int pubkeylen)
        attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :int, :pointer, :int], :int

        # int secp256k1_ecdsa_sign(const secp256k1_context_t* ctx, const unsigned char *msg32, unsigned char *sig, int *siglen, const unsigned char *seckey, secp256k1_nonce_function_t noncefp, const void *ndata)
        attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

        # int secp256k1_ecdsa_sign_compact(const secp256k1_context_t* ctx, const unsigned char *msg32, unsigned char *sig64, const unsigned char *seckey, secp256k1_nonce_function_t noncefp, const void *ndata, int *recid)
        attach_function :secp256k1_ecdsa_sign_compact, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

        # int secp256k1_ecdsa_recover_compact(const secp256k1_context_t* ctx, const unsigned char *msg32, const unsigned char *sig64, unsigned char *pubkey, int *pubkeylen, int compressed, int recid)
        attach_function :secp256k1_ecdsa_recover_compact, [:pointer, :pointer, :pointer, :pointer, :pointer, :int, :int], :int

        # int secp256k1_ec_seckey_verify(const secp256k1_context_t* ctx, const unsigned char *seckey)
        attach_function :secp256k1_ec_seckey_verify, [:pointer, :pointer], :int

        # int secp256k1_ec_pubkey_verify(const secp256k1_context_t* ctx, const unsigned char *pubkey, int pubkeylen)
        attach_function :secp256k1_ec_pubkey_verify, [:pointer, :pointer, :int], :int

        # int secp256k1_ec_pubkey_create(const secp256k1_context_t* ctx, unsigned char *pubkey, int *pubkeylen, const unsigned char *seckey, int compressed)
        attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer, :pointer, :int], :int

        # int secp256k1_ec_pubkey_decompress(const secp256k1_context_t* ctx, unsigned char *pubkey, int *pubkeylen)
        attach_function :secp256k1_ec_pubkey_decompress, [:pointer, :pointer, :pointer], :int

        # int secp256k1_ec_privkey_export(const secp256k1_context_t* ctx, const unsigned char *seckey, unsigned char *privkey, int *privkeylen, int compressed)
        attach_function :secp256k1_ec_privkey_export, [:pointer, :pointer, :pointer, :pointer, :int], :int

        # int secp256k1_ec_privkey_import(const secp256k1_context_t* ctx, unsigned char *seckey, const unsigned char *privkey, int privkeylen)
        attach_function :secp256k1_ec_privkey_import, [:pointer, :pointer, :pointer, :pointer], :int

        # int secp256k1_ec_privkey_tweak_add(const secp256k1_context_t* ctx, unsigned char *seckey, const unsigned char *tweak)
        attach_function :secp256k1_ec_privkey_tweak_add, [:pointer, :pointer, :pointer], :int

        # int secp256k1_ec_pubkey_tweak_add(const secp256k1_context_t* ctx, unsigned char *pubkey, int pubkeylen, const unsigned char *tweak)
        attach_function :secp256k1_ec_pubkey_tweak_add, [:pointer, :pointer, :int, :pointer], :int

        # int secp256k1_ec_privkey_tweak_mul(const secp256k1_context_t* ctx, unsigned char *seckey, const unsigned char *tweak)
        attach_function :secp256k1_ec_privkey_tweak_mul, [:pointer, :pointer, :pointer], :int

        # int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context_t* ctx, unsigned char *pubkey, int pubkeylen, const unsigned char *tweak)
        attach_function :secp256k1_ec_pubkey_tweak_mul, [:pointer, :pointer, :int, :pointer], :int

        # int secp256k1_context_randomize(secp256k1_context_t* ctx, const unsigned char *seed32)
        attach_function :secp256k1_context_randomize, [:pointer, :pointer], :int
      RUBY
    end

    def self.init
      return if @loaded
      lib_path = [ ENV['SECP256K1_LIB_PATH'], 'vendor/bitcoin/src/secp256k1/.libs/libsecp256k1.so' ].find{|f| File.exists?(f.to_s) }
      ffi_load_functions(lib_path)
      @loaded = true
    end

    def self.with_context(flags=nil, seed=nil)
      init
      flags = flags || (SECP256K1_START_VERIFY | SECP256K1_START_SIGN )
      context = secp256k1_context_create(flags)

      ret, tries, max = 0, 0, 20
      while ret != 1
        raise "secp256k1_context_randomize failed." if tries >= max
        tries += 1
        ret = secp256k1_context_randomize(context, FFI::MemoryPointer.from_string(seed || SecureRandom.random_bytes(32)))
      end

      yield(context) if block_given?
    ensure
      secp256k1_context_destroy(context)
    end

    def self.generate_key_pair(compressed=true)
      with_context do |context|

        ret, tries, max = 0, 0, 20
        while ret != 1
          raise "secp256k1_ec_seckey_verify in generate_key_pair failed." if tries >= max
          tries += 1

          priv_key = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.random_bytes(32))
          ret = secp256k1_ec_seckey_verify(context, priv_key)
        end

        pub_key, pub_key_length = FFI::MemoryPointer.new(:uchar, 65), FFI::MemoryPointer.new(:int)
        result = secp256k1_ec_pubkey_create(context, pub_key, pub_key_length, priv_key, compressed ? 1 : 0)
        raise "error creating pubkey" unless result

        [ priv_key.read_string(32), pub_key.read_string(pub_key_length.read_int) ]
      end
    end

    def self.generate_key(compressed=true)
      priv, pub = generate_key_pair(compressed)
      Bitcoin::Key.new(priv.unpack("H*")[0], pub.unpack("H*")[0])
    end

    def self.sign(data, priv_key)
      with_context do |context|
        msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
        seckey = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
        raise "priv_key invalid" unless secp256k1_ec_seckey_verify(context, seckey)

        sig, siglen = FFI::MemoryPointer.new(:uchar, 72), FFI::MemoryPointer.new(:int).write_int(72)

        while true do
          break if secp256k1_ecdsa_sign(context, msg32, sig, siglen, seckey, nil, nil)
        end

        sig.read_string(siglen.read_int)
      end
    end

    def self.verify(data, signature, pub_key)
      with_context do |context|
        data_buf = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
        sig_buf  = FFI::MemoryPointer.new(:uchar, signature.bytesize).put_bytes(0, signature)
        pub_buf  = FFI::MemoryPointer.new(:uchar, pub_key.bytesize).put_bytes(0, pub_key)

        result = secp256k1_ecdsa_verify(context, data_buf, sig_buf, sig_buf.size, pub_buf, pub_buf.size)

        case result
        when  0; false
        when  1; true
        when -1; raise "error invalid pubkey"
        when -2; raise "error invalid signature"
        else   ; raise "error invalid result"
        end
      end
    end

    def self.sign_compact(message, priv_key, compressed=true)
      with_context do |context|
        msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, message)
        sig64 = FFI::MemoryPointer.new(:uchar, 64)
        rec_id = FFI::MemoryPointer.new(:int)

        seckey = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
        raise "priv_key invalid" unless secp256k1_ec_seckey_verify(context, seckey)

        while true do
          break if secp256k1_ecdsa_sign_compact(context, msg32, sig64, seckey, nil, nil, rec_id)
        end

        header = [27 + rec_id.read_int + (compressed ? 4 : 0)].pack("C")
        [ header, sig64.read_string(64) ].join
      end
    end

    def self.recover_compact(message, signature)
      with_context do |context|
        return nil if signature.bytesize != 65

        version = signature.unpack('C')[0]
        return nil if version < 27 || version > 34

        compressed = version >= 31 ? true : false
        version -= 4 if compressed

        recid = version - 27
        msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, message)
        sig64 = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, signature[1..-1])
        pubkey = FFI::MemoryPointer.new(:uchar, pub_key_len = compressed ? 33 : 65)
        pubkeylen = FFI::MemoryPointer.new(:int).write_int(pub_key_len)

        result = secp256k1_ecdsa_recover_compact(context, msg32, sig64, pubkey, pubkeylen, (compressed ? 1 : 0), recid)

        return nil unless result

        pubkey.read_bytes(pubkeylen.read_int)
      end
    end

  end
end
