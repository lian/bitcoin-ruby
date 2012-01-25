require 'bitcoin'

module Bitcoin
  class Script
    OP_1           = 81
    OP_TRUE        = 81
    OP_0           = 0
    OP_FALSE       = 0
    OP_PUSHDATA1   = 76
    OP_PUSHDATA2   = 77
    OP_PUSHDATA4   = 78
    OP_NOP         = 97
    OP_DUP         = 118
    OP_HASH160     = 169
    OP_EQUAL       = 135
    OP_VERIFY      = 105
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
    OP_DROP         = 117
    OP_HASH256      = 170
    OP_SHA256       = 168
    OP_SHA1         = 167
    OP_RIPEMD160    = 166
    OP_EVAL         = 176
    OP_NOP2         = 177

    OPCODES = Hash[*constants.grep(/^OP_/).map{|i| [const_get(i), i.to_s] }.flatten]
    OPCODES[0] = "0"

    OPCODES_ALIAS = { "OP_NOP1" => OP_EVAL }

    OP_2_16 = (82..96).to_a

    attr_reader :raw, :chunks, :debug

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
          when *OPCODES.keys;          OPCODES[i]
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
          when *OPCODES.values;          OPCODES.find{|k,v| v == i }.first
          when *OPCODES_ALIAS.keys;      OPCODES_ALIAS.find{|k,v| k == i }.last
          when /^([2-9]$|1[0-7])$/;      OP_2_16[$1.to_i-2]
          when /\(opcode (\d+)\)/;       $1.to_i
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

    def invalid?
      @script_invalid ||= false
    end

    # Does nothing
    def op_nop
    end

    # Duplicates the top stack item.
    def op_dup
      @stack << @stack[-1].dup
    end

    # The input is hashed using SHA-256.
    def op_sha256
      buf = @stack.pop
      @stack << Digest::SHA256.digest(buf)
    end

    # The input is hashed using SHA-1.
    def op_sha1
      buf = @stack.pop
      @stack << Digest::SHA1.digest(buf)
    end

    # The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
    def op_hash160
      buf = @stack.pop
      @stack << Digest::RMD160.digest(Digest::SHA256.digest(buf))
    end

    # The input is hashed using RIPEMD-160.
    def op_ripemd160
      buf = @stack.pop
      @stack << Digest::RMD160.digest(buf)
    end

    # The input is hashed two times with SHA-256.
    def op_hash256
      buf = @stack.pop
      @stack << Digest::SHA256.digest(Digest::SHA256.digest(buf))
    end

    # Puts the input onto the top of the alt stack. Removes it from the main stack.
    def op_toaltstack
      @stack_alt << @stack.pop
    end

    # Puts the input onto the top of the main stack. Removes it from the alt stack.
    def op_fromaltstack
      @stack << @stack_alt.pop
    end

    # The item at the top of the stack is copied and inserted before the second-to-top item.
    def op_tuck
      @stack[-2..-1] = [ @stack[-1], *@stack[-2..-1] ]
    end

    # The top two items on the stack are swapped.
    def op_swap
      @stack[-2..-1] = @stack[-2..-1].reverse
    end

    # If both a and b are not 0, the output is 1. Otherwise 0.
    def op_booland
      a, b = @stack.pop(2)
      @stack << (![a,b].any?{|n| n == 0 } ? 1 : 0)
    end

    # a is added to b.
    def op_add
      a, b = @stack.pop(2).reverse
      @stack << a + b
    end

    # b is subtracted from a.
    def op_sub
      a, b = @stack.pop(2).reverse
      @stack << a - b
    end

    # Returns 1 if a is greater than or equal to b, 0 otherwise.
    def op_greaterthanorequal
      a, b = @stack.pop(2).reverse
      @stack << (a >= b ? 1 : 0)
    end

    # Removes the top stack item.
    def op_drop
      @stack.pop
    end

    # Returns 1 if the inputs are exactly equal, 0 otherwise.
    def op_equal
      a, b = @stack.pop(2).reverse
      @stack << (a == b ? 1 : 0)
    end

    # Marks transaction as invalid if top stack value is not true. True is removed, but false is not.
    def op_verify
      res = @stack.pop
      if res != 1
        @stack << res
        @script_invalid = true # raise 'transaction invalid' ?
      else
        @script_invalid = false
      end
    end

    # Same as OP_EQUAL, but runs OP_VERIFY afterward.
    def op_equalverify
      op_equal; op_verify
    end

    # An empty array of bytes is pushed onto the stack.
    def op_0
      @stack << "" # []
    end

    # The number 1 is pushed onto the stack.
    def op_1
      @stack << 1
    end

    OPCODES_METHOD = Hash[*instance_methods.grep(/^op_/).map{|m|
      [ (OPCODES.find{|k,v| v == m.to_s.upcase }.first rescue nil), m ]
    }.flatten]
    OPCODES_METHOD[0]  = :op_0


    # run the script. +check_callback+ is called for OP_CHECKSIG operations
    def run(&check_callback)
      @debug = []
      @chunks.each{|chunk|
        break if invalid?
        @debug << @stack.map{|i| i.unpack("H*") rescue i}
        case chunk
        when Fixnum
          case chunk

          when *OPCODES_METHOD.keys
            m = OPCODES_METHOD[chunk]
            @debug << m.to_s.upcase
            send(m) # invoke opcode method

          when *OP_2_16
            @stack << OP_2_16.index(chunk) + 2

          when OP_CHECKSIG
            @debug << "OP_CHECKSIG"
            op_checksig(check_callback)

          when OP_CHECKMULTISIG
            @debug << "OP_CHECKMULTISIG"
            op_checkmultisig(check_callback)

          else
            name = OPCODES[chunk] || chunk
            raise "opcode #{name} unkown or not implemented"
          end
        when String
          @debug << "PUSH DATA #{chunk.unpack("H*")[0]}"
          @stack << chunk
        end
      }
      @debug << @stack.map{|i| i.unpack("H*") rescue i}

      if @script_invalid
        @stack << 0
        @debug << "INVALID TRANSACTION"
      end

      @debug << "RESULT"
      @stack.pop == 1
    end


    # do a CHECKSIG operation on the current stack,
    # asking +check_callback+ to do the actual signature verification.
    # This is used by Protocol::Tx#verify_input_signature
    def op_checksig(check_callback)
      return nil if @stack.size < 2
      pubkey = @stack.pop
      sig, hash_type = parse_sig(@stack.pop)

      if check_callback == nil # for tests
        @stack << 1
      else # real signature check callback
        @stack <<
          ((check_callback.call(pubkey, sig, hash_type) == true) ? 1 : 0)
      end
    end

    # do a CHECKMULTISIG operation on the current stack,
    # asking +check_callback+ to do the actual signature verification.
    #
    # CHECKMULTISIG does a m-of-n signatures verification on scripts of the form:
    #  0 <sig1> <sig2> | 2 <pub1> <pub2> 2 OP_CHECKMULTISIG
    #  0 <sig1> <sig2> | 2 <pub1> <pub2> <pub3> 3 OP_CHECKMULTISIG
    #  0 <sig1> <sig2> <sig3> | 3 <pub1> <pub2> <pub3> 3 OP_CHECKMULTISIG
    #
    # see https://en.bitcoin.it/wiki/BIP_0011 for details.
    #
    # TODO: validate signature order
    def op_checkmultisig(check_callback)
      n_pubkeys = @stack.pop
      return nil  unless n_pubkeys.is_a?(Fixnum)
      return nil  unless @stack.last(n_pubkeys).all?{|e| e.is_a?(String) && e != '' }
      pubkeys = Array.new(n_pubkeys) { @stack.pop }

      n_sigs = @stack.pop
      return nil  unless n_sigs.is_a?(Fixnum)
      return nil  unless @stack.size >= n_sigs
      return nil  unless @stack.last(n_sigs).all?{|e| e.is_a?(String) && e != '' }
      return nil  if n_sigs > n_pubkeys
      sigs = Array.new(n_sigs) { parse_sig(@stack.pop) }

      @stack.pop if @stack[-1] == '' # remove OP_NOP from stack

      valid_sigs = 0
      sigs.each do |sig, hash_type|
        pubkeys.each do |pubkey|
          valid_sigs += 1  if check_callback.call(pubkey, sig, hash_type)
        end
      end

      @stack << 1  if valid_sigs == n_sigs
    end

    # check if script is in one of the recognized standard formats
    def is_standard?
      is_pubkey? || is_hash160?
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
      return Bitcoin.hash160(get_pubkey)        if is_pubkey?
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
      return nil  unless hash160
      #  DUP   HASH160  length  hash160    EQUALVERIFY  CHECKSIG
      [ ["76", "a9",    "14",   hash160,   "88",        "ac"].join ].pack("H*")
    end

    def self.to_signature_pubkey_script(signature, pubkey)
      hash_type = "\x01"
      #pubkey = [pubkey].pack("H*") if pubkey.bytesize != 65
      raise "pubkey is not in binary form" unless pubkey.bytesize == 65  && pubkey[0] == "\x04"
      [ [signature.bytesize+1].pack("C"), signature, hash_type, [pubkey.bytesize].pack("C"), pubkey ].join
    end

    private

    def parse_sig(sig)
      hash_type = sig[-1].unpack("C")[0]
      sig = sig[0...-1]
      return sig, hash_type
    end

  end
end
