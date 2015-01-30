# encoding: ascii-8bit

# Wraps libsecp256k1 (https://github.com/bitcoin/secp256k1)
# commit: 50cc6ab0625efda6dddf1dc86c1e2671f069b0d8

require 'ffi'

module Bitcoin
  module Secp256k1
    extend FFI::Library

    SECP256K1_START_VERIFY = (1 << 0)
    SECP256K1_START_SIGN   = (1 << 1)

    def self.ffi_load_functions(file)
      class_eval <<-RUBY
        ffi_lib [ %[#{file}] ]

        attach_function :secp256k1_start, [:int], :void
        attach_function :secp256k1_stop, [], :void
        attach_function :secp256k1_ec_seckey_verify, [:pointer], :int
        attach_function :secp256k1_ec_pubkey_verify, [:pointer, :int], :int
        attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer, :int], :int

        # int secp256k1_ecdsa_sign(const unsigned char *msg32, unsigned char *sig, int *siglen, const unsigned char *seckey, secp256k1_nonce_function_t noncefp, const void *ndata)
        attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

        # int secp256k1_ecdsa_verify(const unsigned char *msg32, const unsigned char *sig, int siglen, const unsigned char *pubkey, int pubkeylen)
        attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :int, :pointer, :int], :int

        # int secp256k1_ecdsa_sign_compact(const unsigned char *msg32, unsigned char *sig64, const unsigned char *seckey, secp256k1_nonce_function_t noncefp, const void *ndata, int *recid)
        attach_function :secp256k1_ecdsa_sign_compact, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int

        # int secp256k1_ecdsa_recover_compact(const unsigned char *msg32, const unsigned char *sig64, unsigned char *pubkey, int *pubkeylen, int compressed, int recid)
        attach_function :secp256k1_ecdsa_recover_compact, [:pointer, :pointer, :pointer, :pointer, :int, :int], :int
      RUBY
    end

    def self.init
      return if @secp256k1_started

      lib_path = [ ENV['SECP256K1_LIB_PATH'], 'vendor/secp256k1/.libs/libsecp256k1.so' ].find{|f| File.exists?(f.to_s) }
      lib_path = 'libsecp256k1.so' unless lib_path
      ffi_load_functions(lib_path)

      secp256k1_start(SECP256K1_START_VERIFY | SECP256K1_START_SIGN)
      @secp256k1_started = true
    end

    def self.generate_key_pair(compressed=true)
      init

      while true do
        priv_key = SecureRandom.random_bytes(32)
        priv_key_buf = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, priv_key)
        break if secp256k1_ec_seckey_verify(priv_key_buf)
      end

      pub_key_buf = FFI::MemoryPointer.new(:uchar, 65)
      pub_key_size = FFI::MemoryPointer.new(:int)
      result = secp256k1_ec_pubkey_create(pub_key_buf, pub_key_size, priv_key_buf, compressed ? 1 : 0)
      raise "error creating pubkey" unless result

      [ priv_key, pub_key_buf.read_string(pub_key_size.read_int) ]
    end

    def self.sign(data, priv_key)
      init

      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
      seckey = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
      raise "priv_key invalid" unless secp256k1_ec_seckey_verify(seckey)

      sig, siglen = FFI::MemoryPointer.new(:uchar, 72), FFI::MemoryPointer.new(:int).write_int(72)

      while true do
        break if secp256k1_ecdsa_sign(msg32, sig, siglen, seckey, nil, nil)
      end

      sig.read_string(siglen.read_int)
    end

    def self.verify(data, signature, pub_key)
      init

      data_buf = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
      sig_buf  = FFI::MemoryPointer.new(:uchar, signature.bytesize).put_bytes(0, signature)
      pub_buf  = FFI::MemoryPointer.new(:uchar, pub_key.bytesize).put_bytes(0, pub_key)

      result = secp256k1_ecdsa_verify(data_buf, sig_buf, sig_buf.size, pub_buf, pub_buf.size)

      case result
      when  0; false
      when  1; true
      when -1; raise "error invalid pubkey"
      when -2; raise "error invalid signature"
      else   ; raise "error invalid result"
      end
    end

    def self.sign_compact(message, priv_key, compressed=true)
      init

      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, message)
      sig64 = FFI::MemoryPointer.new(:uchar, 64)
      rec_id = FFI::MemoryPointer.new(:int)

      seckey = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
      raise "priv_key invalid" unless secp256k1_ec_seckey_verify(seckey)

      while true do
        break if secp256k1_ecdsa_sign_compact(msg32, sig64, seckey, nil, nil, rec_id)
      end

      header = [27 + rec_id.read_int + (compressed ? 4 : 0)].pack("C")
      [ header, sig64.read_string(64) ].join
    end

    def self.recover_compact(message, signature)
      init

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

      result = secp256k1_ecdsa_recover_compact(msg32, sig64, pubkey, pubkeylen, (compressed ? 1 : 0), recid)

      return nil unless result

      pubkey.read_bytes(pubkeylen.read_int)
    end

  end
end
