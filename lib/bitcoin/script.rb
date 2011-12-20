require 'bitcoin'

module Bitcoin
  class Script
    OP_TRUE        = 81
    OP_1           = 81
    OP_FALSE       = 0
    OP_0           = 0
    OP_2_16        = (82..96).to_a
    OP_PUSHDATA1   = 76
    OP_PUSHDATA2   = 77
    OP_PUSHDATA4   = 78
    OP_DUP         = 118
    OP_HASH160     = 169
    OP_EQUAL       = 135
    OP_EQUALVERIFY = 136
    OP_CHECKSIG    = 172
    OP_CHECKSIGVERIFY      = 173
    OP_CHECKMULTISIG       = 174
    OP_CHECKMULTISIGVERIFY = 175
    OP_TOALTSTACK   = 107
    OP_FROMALTSTACK = 108
    OP_TUCK         = 125
    OP_SWAP         = 124
    OP_BOOLAND      = 154
    OP_ADD          = 147
    OP_SUB          = 148
    OP_GREATERTHANOREQUAL = 162

    attr_reader :raw, :chunks

    # create a new script. +bytes+ is typically input_script + output_script
    def initialize(bytes, offset=0)
      @raw = bytes
      @stack, @stack_alt = [], []
      @chunks = parse(bytes, offset)
    end

    # parse raw script
    def parse(bytes, offset=0)
      program = bytes.unpack("C*")
      chunks = []
      until program.empty?
        opcode = program.shift(1)[0]
        if opcode >= 0xf0
          opcode = (opcode << 8) | program.shift(1)[0]
        end

        if (opcode > 0) && (opcode < OP_PUSHDATA1)
          len = opcode
          chunks << program.shift(len).pack("C*")
        elsif (opcode == OP_PUSHDATA1)
          len = program.shift(1)[0]
          chunks << program.shift(len).pack("C*")
        elsif (opcode == OP_PUSHDATA2)
          len = program.shift(2).pack("C*").unpack("n")[0]
          chunks << program.shift(len).pack("C*")
        elsif (opcode == OP_PUSHDATA4)
          len = program.shift(4).pack("C*").unpack("N")[0]
          chunks << program.shift(len).pack("C*")
        else
          chunks << opcode
        end
      end
      chunks
    end

    # string representation of the script
    def to_string
      @chunks.map{|i|
        case i
        when Fixnum
          case i
          when OP_DUP;         "OP_DUP"
          when OP_HASH160;     "OP_HASH160"
          when OP_CHECKSIG;    "OP_CHECKSIG"
          when OP_EQUAL;       "OP_EQUAL"
          when OP_EQUALVERIFY; "OP_EQUALVERIFY"
          when OP_CHECKSIGVERIFY;      "OP_CHECKSIGVERIFY"
          when OP_CHECKMULTISIG;       "OP_CHECKMULTISIG"
          when OP_CHECKMULTISIGVERIFY; "OP_CHECKMULTISIGVERIFY"
          when OP_TOALTSTACK;          "OP_TOALTSTACK"
          when OP_FROMALTSTACK;        "OP_FROMALTSTACK"
          when OP_TUCK;                "OP_TUCK"
          when OP_SWAP;                "OP_SWAP"
          when OP_BOOLAND;             "OP_BOOLAND"
          when OP_ADD;                 "OP_ADD"
          when OP_SUB;                 "OP_SUB"
          when OP_GREATERTHANOREQUAL;  "OP_GREATERTHANOREQUAL"
          when OP_0;                   "0"
          when OP_1;                   "1"
          when *OP_2_16;               (OP_2_16.index(i)+2).to_s
          else "(opcode #{i})"
          end
        when String
          i.unpack("H*")[0]
        end
      }.join(" ")
    end

    # script object of a string representation
    def self.from_string(script_string)
      new(binary_from_string(script_string))
    end

    # raw script binary of a string representation
    def self.binary_from_string(script_string)
      script_string.split(" ").map{|i|
        case i
          when "OP_DUP";         OP_DUP
          when "OP_HASH160";     OP_HASH160
          when "OP_CHECKSIG";    OP_CHECKSIG
          when "OP_EQUAL";       OP_EQUAL
          when "OP_EQUALVERIFY"; OP_EQUALVERIFY
          when "OP_CHECKSIGVERIFY";      OP_CHECKSIGVERIFY
          when "OP_CHECKMULTISIG";       OP_CHECKMULTISIG
          when "OP_CHECKMULTISIGVERIFY"; OP_CHECKMULTISIGVERIFY
          when "OP_TOALTSTACK";          OP_TOALTSTACK
          when "OP_FROMALTSTACK";        OP_FROMALTSTACK
          when "OP_TUCK";                OP_TUCK
          when "OP_SWAP";                OP_SWAP
          when "OP_BOOLAND";             OP_BOOLAND
          when "OP_ADD";                 OP_ADD
          when "OP_SUB";                 OP_SUB
          when "OP_GREATERTHANOREQUAL";  OP_GREATERTHANOREQUAL
          when "0";                      OP_0
          when "OP_FALSE";               OP_0
          when "1";                      OP_1
          when "OP_TRUE";                OP_1
          when /^([2-9]$|1[0-7])$/;      OP_2_16[$1.to_i-2]
          when /\(opcode (\d+)\)/; $1.to_i
          else 
            data = [i].pack("H*")
            size = data.bytesize

            head = if size < OP_PUSHDATA1
              [size].pack("C")
            elsif size > OP_PUSHDATA1 && size <= 0xff
              [OP_PUSHDATA1, size].pack("CC")
            elsif size > 0xff && size <= 0xffff
              [OP_PUSHDATA2, size].pack("Cn")
            elsif size > 0xffff && size <= 0xffffffff
              [OP_PUSHDATA4, size].pack("CN")
            end

            head + data
        end
      }.map{|i|
        i.is_a?(Fixnum) ? [i].pack("C*") : i # TODO yikes, implement/pack 2 byte opcodes.
      }.join
    end

    # run the script. +check_callback+ is called for OP_CHECKSIG operations
    def run(debug = [], &check_callback)
      @chunks.each{|chunk|
        debug << @stack.map{|i| i.unpack("H*")}
        case chunk
        when Fixnum
          case chunk
          when OP_DUP
            debug << "OP_DUP"
            @stack << @stack[-1].dup
          when OP_HASH160
            debug << "OP_HASH160"
            buf = @stack.pop
            @stack << Digest::RMD160.digest(Digest::SHA256.digest(buf))
          when OP_CHECKSIG
            debug << "OP_CHECKSIG"
            op_checksig(check_callback)
          when OP_EQUALVERIFY
            debug << "OP_EQUALVERIFY"
            a, b = @stack.pop(2).reverse
            return :EQUALVERIFY_FAILED if a != b
          when OP_CHECKSIGVERIFY
            raise "opcode OP_CHECKSIGVERIFY not implemented yet."
          when OP_CHECKMULTISIG
            raise "opcode OP_CHECKMULTISIG not implemented yet."
          when OP_CHECKMULTISIGVERIFY
            raise "opcode OP_CHECKMULTISIGVERIFY not implemented yet."
          when OP_TOALTSTACK
            # Puts the input onto the top of the alt stack. Removes it from the main stack.
            @stack_alt << @stack.pop(1)
          when OP_FROMALTSTACK
            # Puts the input onto the top of the main stack. Removes it from the alt stack.
            @stack << @stack_alt.pop(1)
          when OP_TUCK
            # The item at the top of the stack is copied and inserted before the second-to-top item.
            @stack[-2..-1] = [ @stack[-1], *@stack[-2..-1] ]
          when OP_SWAP
            @stack[-2..-1] = @stack[-2..-1].reverse
          when OP_BOOLAND
            # If both a and b are not 0, the output is 1. Otherwise 0.
            a, b = @stack.pop(2)
            @stack << ![a,b].any?{|n| n == 0 } ? 1 : 0
          when OP_ADD
            a, b = @stack.pop(2).reverse
            @stack << a + b
          when OP_SUB
            a, b = @stack.pop(2).reverse
            @stack << a - b
          when OP_GREATERTHANOREQUAL
            a, b = @stack.pop(2).reverse
            @stack << (a >= b) ? 1 : 0
          when OP_0
            # An empty array of bytes is pushed onto the stack.
            @stack << "" # []
          when OP_1
            @stack << 1
          when OP_2_16
            @stack << OP_2_16.index(chunk)+2
          else raise "opcode #{i} unkown or not implemented"
          end
        when String
          debug << "PUSH DATA #{chunk.unpack("H*")[0]}"
          @stack << chunk
        end
      }
      debug << @stack.map{|i| i.unpack("H*") rescue i}
      debug << "RESULT"
      @stack.pop == true
    end

    # do a CHECKSIG operation on the current stack,
    # asking +check_callback+ to do the actual signature verification.
    # This is used by Protocol::Tx#verify_input_signature
    def op_checksig(check_callback)
      return nil if @stack.size < 2
      pubkey = @stack.pop
      sig_and_hash_type = @stack.pop
      hash_type = sig_and_hash_type[-1].unpack("C")[0]
      sig       = sig_and_hash_type[0...-1]

      if check_callback == nil # for tests
        @stack << true
      else # real signature check callback
        @stack <<
          (check_callback.call(pubkey, sig, hash_type) == true)
      end
    end

    def is_standard? # TODO: add
      # https://github.com/bitcoin/bitcoin/blob/master/src/script.cpp#L967
    end

    # is this a send-to-ip (pubkey) tx
    def is_send_to_ip?
      return false if @chunks.size != 2
      (@chunks[1] == OP_CHECKSIG) && @chunks[0].size > 1
    end
    alias :is_pubkey? :is_send_to_ip?

    # is this a hash160 (address) tx
    def is_hash160?
      return false  if @chunks.size != 5
      (@chunks[0..1] + @chunks[-2..-1]) ==
        [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] &&
        @chunks[2].is_a?(String) && @chunks[2].bytesize == 20
    end

    # get the public key for this script (in generation scripts)
    def get_pubkey
      return @chunks[0].unpack("H*")[0] if @chunks.size == 1
      is_pubkey? ? @chunks[0].unpack("H*")[0] : nil
    end

    # get the address for the public key (in generation scripts)
    def get_pubkey_address
      Bitcoin.pubkey_to_address(get_pubkey)
    end

    # get the hash160 for this script (in standard address scripts)
    def get_hash160
      return @chunks[2..-3][0].unpack("H*")[0]  if is_hash160?
      return Bitcoin.hash160(get_pubkey)  if is_pubkey?
    end

    # get the address for the script hash160 (in standard address scripts)
    def get_hash160_address
      Bitcoin.hash160_to_address(get_hash160)
    end

    # get address this script corresponds to (if possible)
    def get_address
      return get_pubkey_address  if is_pubkey?
      return get_hash160_address if is_hash160?
    end

    # generate standard transaction script for given +address+
    def self.to_address_script(address)
      hash160 = Bitcoin.hash160_from_address(address)
      #  DUP   HASH160  length  hash160    EQUALVERIFY  CHECKSIG
      [ ["76", "a9",    "14",   hash160,   "88",        "ac"].join ].pack("H*")
    end

    def self.to_signature_pubkey_script(signature, pubkey)
      hash_type = "\x01"
      #pubkey = [pubkey].pack("H*") if pubkey.bytesize != 65
      raise "pubkey is not in binary form" unless pubkey.bytesize == 65  && pubkey[0] == "\x04"
      [ [signature.bytesize+1].pack("C"), signature, hash_type, [pubkey.bytesize].pack("C"), pubkey ].join
    end
  end
end
