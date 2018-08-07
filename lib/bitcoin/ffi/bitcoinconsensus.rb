# encoding: ascii-8bit

require 'ffi'

module Bitcoin
  # binding for src/.libs/bitcoinconsensus.so (https://github.com/bitcoin/bitcoin)
  # tag: v0.11.0
  # commit: d26f951802c762de04fb68e1a112d611929920ba
  module BitcoinConsensus
    extend FFI::Library

    SCRIPT_VERIFY_NONE      = 0
    SCRIPT_VERIFY_P2SH      = (1 << 0)
    SCRIPT_VERIFY_STRICTENC = (1 << 1)
    SCRIPT_VERIFY_DERSIG    = (1 << 2)
    SCRIPT_VERIFY_LOW_S     = (1 << 3)
    SCRIPT_VERIFY_NULLDUMMY = (1 << 4)
    SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)
    SCRIPT_VERIFY_MINIMALDATA = (1 << 6)
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)
    SCRIPT_VERIFY_CLEANSTACK = (1 << 8)

    ERR_CODES = { 0 => :ok, 1 => :tx_index, 2 => :tx_size_mismatch, 3 => :tx_deserialize }.freeze

    def self.ffi_load_functions(file)
      class_eval <<-RUBY # rubocop:disable Style/EvalWithLocation
        ffi_lib [ %[#{file}] ]
        attach_function :bitcoinconsensus_version, [], :uint

        # int bitcoinconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
        #                                    const unsigned char *txTo        , unsigned int txToLen,
        #                                    unsigned int nIn, unsigned int flags, bitcoinconsensus_error* err);
        attach_function :bitcoinconsensus_verify_script, [:pointer, :uint, :pointer, :uint, :uint, :uint, :pointer], :int
      RUBY
    end

    def self.lib_available?
      @__lib_path ||= [ # rubocop:disable Naming/MemoizedInstanceVariableName
        ENV['BITCOINCONSENSUS_LIB_PATH'], 'vendor/bitcoin/src/.libs/libbitcoinconsensus.so'
      ].find { |f| File.exist?(f.to_s) }
    end

    def self.init
      return if @bitcoin_consensus
      lib_path = lib_available?
      ffi_load_functions(lib_path)
      @bitcoin_consensus = true
    end

    # api version
    def self.version
      init
      bitcoinconsensus_version
    end

    def self.verify_script(input_index, script_pubkey, tx_payload, script_flags)
      init

      script_pub_key = FFI::MemoryPointer.new(
        :uchar, script_pubkey.bytesize
      ).put_bytes(0, script_pubkey)
      tx_to = FFI::MemoryPointer.new(:uchar, tx_payload.bytesize).put_bytes(0, tx_payload)
      error_ret = FFI::MemoryPointer.new(:uint)

      ret = bitcoinconsensus_verify_script(
        script_pub_key, script_pub_key.size, tx_to, tx_to.size, input_index, script_flags, error_ret
      )

      case ret
      when 0
        false
      when 1
        ERR_CODES[error_ret.read_int] == :ok
      else
        raise 'error invalid result'
      end
    end
  end
end
