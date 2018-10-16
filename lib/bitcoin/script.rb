# encoding: ascii-8bit

require 'bitcoin'

module Bitcoin
  # Bitcoin script parsing
  class Script # rubocop:disable Metrics/ClassLength
    OP_0           = 0
    OP_FALSE       = 0
    OP_1           = 81
    OP_TRUE        = 81
    OP_2           = 0x52
    OP_3           = 0x53
    OP_4           = 0x54
    OP_5           = 0x55
    OP_6           = 0x56
    OP_7           = 0x57
    OP_8           = 0x58
    OP_9           = 0x59
    OP_10          = 0x5a
    OP_11          = 0x5b
    OP_12          = 0x5c
    OP_13          = 0x5d
    OP_14          = 0x5e
    OP_15          = 0x5f
    OP_16          = 0x60

    OP_PUSHDATA0   = 0
    OP_PUSHDATA1   = 76
    OP_PUSHDATA2   = 77
    OP_PUSHDATA4   = 78
    OP_PUSHDATA_INVALID = 238 # 0xEE
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
    OP_NOP1         = 176
    OP_NOP2         = 177
    OP_NOP3         = 178
    OP_NOP4         = 179
    OP_NOP5         = 180
    OP_NOP6         = 181
    OP_NOP7         = 182
    OP_NOP8         = 183
    OP_NOP9         = 184
    OP_NOP10        = 185
    OP_CODESEPARATOR = 171
    OP_MIN          = 163
    OP_MAX          = 164
    OP_2OVER        = 112
    OP_2ROT         = 113
    OP_2SWAP        = 114
    OP_IFDUP        = 115
    OP_DEPTH        = 116
    OP_1NEGATE      = 79
    OP_WITHIN         = 165
    OP_NUMEQUAL       = 156
    OP_NUMEQUALVERIFY = 157
    OP_LESSTHAN = 159
    OP_LESSTHANOREQUAL = 161
    OP_GREATERTHAN = 160
    OP_NOT = 145
    OP_0NOTEQUAL = 146
    OP_ABS = 144
    OP_1ADD = 139
    OP_1SUB = 140
    OP_NEGATE = 143
    OP_BOOLOR = 155
    OP_NUMNOTEQUAL = 158
    OP_RETURN = 106
    OP_OVER = 120
    OP_IF = 99
    OP_NOTIF = 100
    OP_ELSE = 103
    OP_ENDIF = 104
    OP_PICK = 121
    OP_SIZE = 130
    OP_VER = 98
    OP_ROLL = 122
    OP_ROT = 123
    OP_2DROP = 109
    OP_2DUP = 110
    OP_3DUP = 111
    OP_NIP = 119

    OP_CAT = 126
    OP_SUBSTR = 127
    OP_LEFT = 128
    OP_RIGHT = 129
    OP_INVERT = 131
    OP_AND = 132
    OP_OR = 133
    OP_XOR = 134
    OP_2MUL = 141
    OP_2DIV = 142
    OP_MUL = 149
    OP_DIV = 150
    OP_MOD = 151
    OP_LSHIFT = 152
    OP_RSHIFT = 153

    OP_INVALIDOPCODE = 0xff

    OPCODES = Hash[*constants.grep(/^OP_/).map { |i| [const_get(i), i.to_s] }.flatten]
    OPCODES[0] = '0'
    OPCODES[81] = '1'

    # rubocop:disable Style/MutableConstant
    OPCODES_ALIAS = {
      'OP_TRUE'  => OP_1,
      'OP_FALSE' => OP_0,
      'OP_EVAL' => OP_NOP1,
      'OP_CHECKHASHVERIFY' => OP_NOP2
    }

    DISABLED_OPCODES = [
      OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT,
      OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_MUL,
      OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT
    ]

    OP_2_16 = (82..96).to_a

    OPCODES_PARSE_BINARY = {}
    OPCODES.each { |k, v| OPCODES_PARSE_BINARY[k] = v }
    OP_2_16.each { |i| OPCODES_PARSE_BINARY[i] = (OP_2_16.index(i) + 2).to_s }

    OPCODES_PARSE_STRING = {}
    OPCODES.each { |k, v|       OPCODES_PARSE_STRING[v] = k }
    OPCODES_ALIAS.each { |k, v| OPCODES_PARSE_STRING[k] = v }
    2.upto(16).each { |i|      OPCODES_PARSE_STRING["OP_#{i}"] = OP_2_16[i - 2] }
    2.upto(16).each { |i|      OPCODES_PARSE_STRING[i.to_s] = OP_2_16[i - 2] }
    [1, 2, 4].each { |i| OPCODES_PARSE_STRING.delete("OP_PUSHDATA#{i}") }

    SIGHASH_TYPE = {
      all: 1,
      none: 2,
      single: 3,
      forkid: 64,
      anyonecanpay: 128
    }
    # rubocop:enable Style/MutableConstant

    attr_reader :raw, :chunks, :debug, :stack

    # create a new script. +bytes+ is typically input_script + output_script

    def initialize(input_script, previous_output_script = nil)
      @raw_byte_sizes = [
        input_script.bytesize,
        previous_output_script ? previous_output_script.bytesize : 0
      ]
      @input_script = input_script
      @previous_output_script = previous_output_script
      @parse_invalid = nil
      @inner_p2sh = nil
      @script_codeseparator_index = nil

      @raw = if @previous_output_script
               @input_script + [Bitcoin::Script::OP_CODESEPARATOR].pack('C') \
                             + @previous_output_script
             else
               @input_script
             end

      @chunks = parse(@input_script)

      if previous_output_script
        @script_codeseparator_index = @chunks.size
        @chunks << Bitcoin::Script::OP_CODESEPARATOR
        @chunks += parse(@previous_output_script)
      end

      @stack = []
      @stack_alt = []
      @exec_stack = []
      @last_codeseparator_index = 0
      @do_exec = true
    end

    # String utils
    class ::String # rubocop:disable Style/ClassAndModuleChildren
      attr_accessor :bitcoin_pushdata
      attr_accessor :bitcoin_pushdata_length
    end

    # parse raw script
    # rubocop:disable Metrics/BlockNesting
    # rubocop:disable Metrics/CyclomaticComplexity
    # rubocop:disable Metrics/PerceivedComplexity
    def parse(bytes, _offset = 0)
      program = bytes.unpack('C*')
      chunks = []
      until program.empty?
        opcode = program.shift

        if (opcode > 0) && (opcode < OP_PUSHDATA1)
          len = opcode
          tmp = program[0]
          chunks << program.shift(len).pack('C*')

          # 0x16 = 22 due to OP_2_16 from_string parsing
          if len == 1 && tmp && tmp <= 22
            chunks.last.bitcoin_pushdata = OP_PUSHDATA0
            chunks.last.bitcoin_pushdata_length = len
          elsif len != chunks.last.bytesize
            raise 'invalid OP_PUSHDATA0'
          end
        elsif opcode == OP_PUSHDATA1
          len = program.shift(1)[0]
          chunks << program.shift(len).pack('C*')

          if len > OP_PUSHDATA1 && len <= 0xff
            raise 'invalid OP_PUSHDATA1' if len != chunks.last.bytesize
          else
            chunks.last.bitcoin_pushdata = OP_PUSHDATA1
            chunks.last.bitcoin_pushdata_length = len
          end
        elsif opcode == OP_PUSHDATA2
          len = program.shift(2).pack('C*').unpack('v')[0]
          chunks << program.shift(len).pack('C*')

          if len > 0xff && len <= 0xffff
            raise 'invalid OP_PUSHDATA2' if len != chunks.last.bytesize
          else
            chunks.last.bitcoin_pushdata = OP_PUSHDATA2
            chunks.last.bitcoin_pushdata_length = len
          end
        elsif opcode == OP_PUSHDATA4
          len = program.shift(4).pack('C*').unpack('V')[0]
          chunks << program.shift(len).pack('C*')

          if len > 0xffff
            raise 'invalid OP_PUSHDATA4' if len != chunks.last.bytesize
          else # && len <= 0xffffffff
            chunks.last.bitcoin_pushdata = OP_PUSHDATA4
            chunks.last.bitcoin_pushdata_length = len
          end
        else
          chunks << opcode
        end
      end
      chunks
    rescue StandardError => ex
      # bail out! #run returns false but serialization roundtrips still create the right payload.
      chunks.pop if ex.message.include?('invalid OP_PUSHDATA')
      @parse_invalid = true
      c = bytes.unpack('C*').pack('C*')
      c.bitcoin_pushdata = OP_PUSHDATA_INVALID
      c.bitcoin_pushdata_length = c.bytesize
      chunks << c
    end
    # rubocop:enable Metrics/BlockNesting
    # rubocop:enable Metrics/CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity

    # string representation of the script
    def to_string(chunks = nil)
      string = ''
      (chunks || @chunks).each.with_index do |i, idx|
        string << ' ' unless idx == 0
        string << case i
                  when Bitcoin::Integer
                    opcode = OPCODES_PARSE_BINARY[i]
                    opcode || "(opcode-#{i})"
                  when String
                    if i.bitcoin_pushdata
                      base_str = "#{i.bitcoin_pushdata}:#{i.bitcoin_pushdata_length}:"
                      base_str.force_encoding('binary') + i.unpack('H*')[0]
                    else
                      i.unpack('H*')[0]
                    end
                  end
      end
      string
    end

    def to_binary(chunks = nil)
      (chunks || @chunks).map do |chunk|
        case chunk
        when Bitcoin::Integer then [chunk].pack('C*')
        when String then self.class.pack_pushdata(chunk)
        end
      end.join
    end
    alias to_payload to_binary

    def to_binary_without_signatures(drop_signatures, chunks = nil)
      buf = []
      (chunks || @chunks).each.with_index do |chunk, idx|
        if (chunk == OP_CODESEPARATOR) && (idx <= @last_codeseparator_index)
          buf.clear
        elsif chunk == OP_CODESEPARATOR
          break if idx == @script_codeseparator_index
        elsif drop_signatures.none? { |e| e == chunk }
          buf << chunk
        end
      end
      to_binary(buf)
    end

    # Returns a script that deleted the script before the index specified by separator_index.
    def subscript_codeseparator(separator_index)
      buf = []
      process_separator_index = 0
      (chunks || @chunks).each  do |chunk|
        buf << chunk if process_separator_index == separator_index
        if chunk == OP_CODESEPARATOR && process_separator_index < separator_index
          process_separator_index += 1
        end
      end
      to_binary(buf)
    end

    # Adds opcode (OP_0, OP_1, ... OP_CHECKSIG etc.)
    # Returns self.
    def append_opcode(opcode)
      raise 'Opcode should be an integer' unless opcode.is_a?(Bitcoin::Integer)
      raise 'Opcode should be within [0x00, 0xff]' unless opcode >= OP_0 && opcode <= 0xff
      @chunks << opcode
      self
    end

    # Adds the opcode corresponding to the given number. Returns self.
    def append_number(number)
      opcode =
        case number
        when -1 then OP_1NEGATE
        when 0 then OP_0
        when 1 then OP_1
        when 2..16 then OP_2 + (16 - number)
        end
      raise "No opcode for number #{number}" if opcode.nil?
      append_opcode(opcode)
    end

    # Adds binary string as pushdata. Pushdata will be encoded in the most compact form
    # (unless the string contains internal info about serialization that's added by Script class)
    # Returns self.
    def append_pushdata(pushdata_string)
      raise 'Pushdata should be a string' unless pushdata_string.is_a?(String)
      @chunks << pushdata_string
      self
    end

    def self.pack_pushdata(data)
      size = data.bytesize

      if data.bitcoin_pushdata
        size = data.bitcoin_pushdata_length
        pack_pushdata_align(data.bitcoin_pushdata, size, data)
      else
        head = if size < OP_PUSHDATA1
                 [size].pack('C')
               elsif size <= 0xff
                 [OP_PUSHDATA1, size].pack('CC')
               elsif size <= 0xffff
                 [OP_PUSHDATA2, size].pack('Cv')
               # elsif size <= 0xffffffff
               else
                 [OP_PUSHDATA4, size].pack('CV')
               end
        head + data
      end
    end

    def self.pack_pushdata_align(pushdata, len, data)
      case pushdata
      when OP_PUSHDATA1
        [OP_PUSHDATA1, len].pack('CC') + data
      when OP_PUSHDATA2
        [OP_PUSHDATA2, len].pack('Cv') + data
      when OP_PUSHDATA4
        [OP_PUSHDATA4, len].pack('CV') + data
      when OP_PUSHDATA_INVALID
        data
      else # OP_PUSHDATA0
        [len].pack('C') + data
      end
    end

    # script object of a string representation
    def self.from_string(input_script, previous_output_script = nil)
      if previous_output_script
        new(binary_from_string(input_script), binary_from_string(previous_output_script))
      else
        new(binary_from_string(input_script))
      end
    end

    class ScriptOpcodeError < StandardError; end

    # raw script binary of a string representation
    # rubocop:disable Metrics/CyclomaticComplexity
    def self.binary_from_string(script_string)
      buf = ''
      script_string.split(' ').each do |i|
        opcode = OPCODES_PARSE_STRING[i]
        i = opcode ||
            case i
            when /OP_PUSHDATA/ then nil # skip
            when /OP_(.+)$/ then               raise ScriptOpcodeError, "#{i} not defined!"
            when /\(opcode\-(\d+)\)/ then      Regexp.last_match(1).to_i
            when '(opcode' then nil # skip  # fix invalid opcode parsing
            when /^(\d+)\)/ then Regexp.last_match(1).to_i # fix invalid opcode parsing
            when /(\d+):(\d+):(.+)?/
              pushdata = Regexp.last_match(1).to_i
              len = Regexp.last_match(2).to_i
              data = Regexp.last_match(3)
              pack_pushdata_align(pushdata, len, [data].pack('H*'))
            else
              data = [i].pack('H*')
              pack_pushdata(data)
            end

        next unless i
        buf << if i.is_a?(Bitcoin::Integer)
                 i < 256 ? [i].pack('C') : [OpenSSL::BN.new(i.to_s, 10).to_hex].pack('H*')
               else
                 i
               end
      end
      buf
    end
    # rubocop:enable Metrics/CyclomaticComplexity

    def invalid?
      @script_invalid ||= false # rubocop:disable Naming/MemoizedInstanceVariableName
    end

    # run the script. +check_callback+ is called for OP_CHECKSIG operations
    # rubocop:disable Metrics/CyclomaticComplexity
    # rubocop:disable Metrics/PerceivedComplexity
    def run(block_timestamp = Time.now.to_i, opts = {}, &check_callback)
      return false if @parse_invalid

      # p [to_string, block_timestamp, p2sh?]
      @script_invalid = true if @raw_byte_sizes.any? { |size| size > 10_000 }
      @last_codeseparator_index = 0

      if block_timestamp >= 1_333_238_400 # Pay to Script Hash (BIP 0016)
        return pay_to_script_hash(block_timestamp, opts, check_callback) if p2sh?
      end

      @debug = []
      @chunks.each.with_index do |chunk, idx|
        break if invalid?
        @chunk_last_index = idx

        @debug << @stack.map do |i|
          begin
            i.unpack('H*')
          rescue StandardError
            i
          end
        end
        @do_exec = @exec_stack.count(false) == 0
        # p [@stack, @do_exec]

        case chunk
        when Bitcoin::Integer
          if DISABLED_OPCODES.include?(chunk)
            @script_invalid = true
            @debug << "DISABLED_#{OPCODES[chunk]}"
            break
          end

          next @debug.pop unless @do_exec || (OP_IF <= chunk && chunk <= OP_ENDIF)

          case chunk
          when *OPCODES_METHOD.keys
            m = method(n = OPCODES_METHOD[chunk])
            @debug << n.to_s.upcase
            # invoke opcode method
            case m.arity
            when 0
              m.call
            when 1
              m.call(check_callback)
            when -2 # One fixed parameter, one optional
              m.call(check_callback, opts)
            else
              puts "Bitcoin::Script: opcode #{name} method parameters invalid"
            end
          when *OP_2_16
            @stack << OP_2_16.index(chunk) + 2
            @debug << "OP_#{chunk - 80}"
          else
            name = OPCODES[chunk] || chunk
            puts "Bitcoin::Script: opcode #{name} unkown or not implemented\n#{to_string.inspect}"
            raise "opcode #{name} unkown or not implemented"
          end
        when String
          if @do_exec
            @debug << "PUSH DATA #{chunk.unpack('H*')[0]}"
            @stack << chunk
          else
            @debug.pop
          end
        end
      end
      @debug << @stack.map do |i|
        begin
                       i.unpack('H*')
                     rescue StandardError
                       i
                     end
      end

      if @script_invalid
        @stack << 0
        @debug << 'INVALID TRANSACTION'
      end

      @debug << 'RESULT'
      return false if @stack.empty?
      return false if cast_to_bool(@stack.pop) == false
      true
    end
    # rubocop:enable Metrics/CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity

    def invalid
      @script_invalid = true
      nil
    end

    def self.drop_signatures(script_pubkey, drop_signatures)
      script = new(script_pubkey).to_string.split(' ').delete_if do |c|
        drop_signatures.include?(c)
      end.join(' ')
      binary_from_string(script)
    end

    # pay_to_script_hash: https://en.bitcoin.it/wiki/BIP_0016
    #
    # <sig> {<pub> OP_CHECKSIG} | OP_HASH160 <script_hash> OP_EQUAL
    def pay_to_script_hash(block_timestamp, opts, check_callback)
      return false if @chunks.size < 4
      *rest, script, _, script_hash, _ = @chunks
      script = rest.pop if script == OP_CODESEPARATOR
      script = cast_to_string(script)
      script_hash = cast_to_string(script_hash)

      return false unless Bitcoin.hash160(script.unpack('H*')[0]) == script_hash.unpack('H*')[0]
      return true  if check_callback == :check

      script = self.class.new(to_binary(rest) + script).inner_p2sh!(script)
      result = script.run(block_timestamp, opts, &check_callback)
      @debug = script.debug

      # Set the execution stack to match the redeem script, so checks on stack contents
      # at end of script execution validate correctly
      @stack = script.stack
      result
    end

    def inner_p2sh!(script = nil)
      @inner_p2sh = true
      @inner_script_code = script
      self
    end

    def inner_p2sh?
      @inner_p2sh
    end

    # get the inner p2sh script
    def inner_p2sh_script
      return nil if @chunks.size < 4
      *rest, script, _, script_hash, _ = @chunks
      script = rest.pop if script == OP_CODESEPARATOR
      script = cast_to_string(script)
      script_hash = cast_to_string(script_hash)

      return nil unless Bitcoin.hash160(script.unpack('H*')[0]) == script_hash.unpack('H*')[0]
      script
    end

    # is this a :script_hash (pay-to-script-hash/p2sh) script?
    # rubocop:disable Metrics/CyclomaticComplexity
    # rubocop:disable Metrics/PerceivedComplexity
    def pay_to_script_hash?
      @inner_p2sh ||= false
      return false if @inner_p2sh
      if @previous_output_script
        chunks = Bitcoin::Script.new(@previous_output_script).chunks
        chunks.size == 3 &&
          chunks[-3] == OP_HASH160 &&
          chunks[-2].is_a?(String) && chunks[-2].bytesize == 20 &&
          chunks[-1] == OP_EQUAL
      else
        @chunks.size >= 3 &&
          @chunks[-3] == OP_HASH160 &&
          @chunks[-2].is_a?(String) && @chunks[-2].bytesize == 20 &&
          @chunks[-1] == OP_EQUAL &&
          # make sure the script_sig matches the p2sh hash from the pk_script (if there is one)
          (@chunks.size > 3 ? pay_to_script_hash(nil, nil, :check) : true)
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity

    # check if script is in one of the recognized standard formats
    def standard?
      pubkey? || hash160? \
              || multisig? \
              || p2sh? \
              || op_return? \
              || witness_v0_keyhash? \
              || witness_v0_scripthash?
    end

    # is this a pubkey script
    def pubkey?
      return false if @chunks.size != 2
      (@chunks[1] == OP_CHECKSIG) && @chunks[0] \
                                  && @chunks[0].is_a?(String) \
                                  && @chunks[0] != OP_RETURN
    end

    # is this a hash160 (address) script
    def hash160?
      return false if @chunks.size != 5
      (@chunks[0..1] + @chunks[-2..-1]) ==
        [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] &&
        @chunks[2].is_a?(String) && @chunks[2].bytesize == 20
    end

    # is this a multisig script
    def multisig?
      return false if @chunks.size < 4 || !@chunks[-2].is_a?(Bitcoin::Integer)
      (@chunks[-1] == OP_CHECKMULTISIG) && get_multisig_pubkeys.all? { |c| c.is_a?(String) }
    end

    # is this an op_return script
    def op_return?
      @chunks[0] == OP_RETURN && @chunks.size <= 2
    end

    # is this a witness script
    def witness?
      @chunks.length == 2 && (0..16).cover?(@chunks[0]) && @chunks[1].is_a?(String)
    end

    # is this a witness pubkey script
    def witness_v0_keyhash?
      witness? && @chunks[0] == 0 && @chunks[1].bytesize == 20
    end

    # is this a witness script hash
    def witness_v0_scripthash?
      witness? && @chunks[0] == 0 && @chunks[1].bytesize == 32
    end

    # Verify the script is only pushing data onto the stack
    def push_only?(script_data = nil)
      check_pushes(true, false, (script_data || @input_script))
    end

    # Make sure opcodes used to push data match their intended length ranges
    def pushes_are_canonical?(script_data = nil)
      check_pushes(false, true, (script_data || @raw))
    end

    # rubocop:disable Metrics/CyclomaticComplexity
    # rubocop:disable Metrics/PerceivedComplexity
    # rubocop:disable Style/OptionalArguments
    def check_pushes(push_only = true, canonical_only = false, buf)
      program = buf.unpack('C*')
      until program.empty?
        opcode = program.shift
        if opcode > OP_16
          return false if push_only
          next
        end
        if opcode < OP_PUSHDATA1 && opcode > OP_0
          # Could have used an OP_n code, rather than a 1-byte push.
          return false if canonical_only && opcode == 1 && program[0] <= 16
          program.shift(opcode)
        end
        if opcode == OP_PUSHDATA1
          len = program.shift(1)[0]
          # Could have used a normal n-byte push, rather than OP_PUSHDATA1.
          return false if canonical_only && len < OP_PUSHDATA1
          program.shift(len)
        end
        if opcode == OP_PUSHDATA2
          len = program.shift(2).pack('C*').unpack('v')[0]
          # Could have used an OP_PUSHDATA1.
          return false if canonical_only && len <= 0xff
          program.shift(len)
        end
        next unless opcode == OP_PUSHDATA4
        len = program.shift(4).pack('C*').unpack('V')[0]
        # Could have used an OP_PUSHDATA2.
        return false if canonical_only && len <= 0xffff
        program.shift(len)
      end
      true
    rescue StandardError
      # catch parsing errors
      false
    end
    # rubocop:enable Metrics/CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity
    # rubocop:enable Style/OptionalArguments

    # get type of this tx
    def type
      if hash160?
        :hash160
      elsif pubkey?
        :pubkey
      elsif multisig?
        :multisig
      elsif p2sh?
        :p2sh
      elsif op_return?
        :op_return
      elsif witness_v0_keyhash?
        :witness_v0_keyhash
      elsif witness_v0_scripthash?
        :witness_v0_scripthash
      else
        :unknown
      end
    end

    # get the public key for this pubkey script
    def get_pubkey # rubocop:disable Naming/AccessorMethodName
      return @chunks[0].unpack('H*')[0] if @chunks.size == 1
      pubkey? ? @chunks[0].unpack('H*')[0] : nil
    end

    # get the pubkey address for this pubkey script
    def get_pubkey_address # rubocop:disable Naming/AccessorMethodName
      Bitcoin.pubkey_to_address(get_pubkey)
    end

    # get the hash160 for this hash160 or pubkey script
    def get_hash160 # rubocop:disable Naming/AccessorMethodName
      return @chunks[2..-3][0].unpack('H*')[0] if hash160?
      return @chunks[-2].unpack('H*')[0]       if p2sh?
      return Bitcoin.hash160(get_pubkey)       if pubkey?
      return @chunks[1].unpack('H*')[0]        if witness_v0_keyhash?
      return @chunks[1].unpack('H*')[0]        if witness_v0_scripthash?
    end

    # get the hash160 address for this hash160 script
    def get_hash160_address # rubocop:disable Naming/AccessorMethodName
      Bitcoin.hash160_to_address(get_hash160)
    end

    # get the public keys for this multisig script
    def get_multisig_pubkeys # rubocop:disable Naming/AccessorMethodName
      1.upto(@chunks[-2] - 80).map { |i| @chunks[i] }
    end

    # get the pubkey addresses for this multisig script
    def get_multisig_addresses # rubocop:disable Naming/AccessorMethodName
      get_multisig_pubkeys.map do |pub|
        begin
          Bitcoin::Key.new(nil, pub.unpack('H*')[0]).addr
        rescue OpenSSL::PKey::ECError, OpenSSL::PKey::EC::Point::Error => e
          puts e
        end
      end
    end

    def get_p2sh_address # rubocop:disable Naming/AccessorMethodName
      Bitcoin.hash160_to_p2sh_address(get_hash160)
    end

    # get the data possibly included in an OP_RETURN script
    def get_op_return_data # rubocop:disable Naming/AccessorMethodName
      return nil  unless op_return?
      cast_to_string(@chunks[1]).unpack('H*')[0] if @chunks[1]
    end

    # get all addresses this script corresponds to (if possible)
    def get_addresses # rubocop:disable Naming/AccessorMethodName
      return [get_pubkey_address]   if pubkey?
      return [get_hash160_address]  if hash160?
      return get_multisig_addresses if multisig?
      return [get_p2sh_address]     if p2sh?

      if witness_v0_keyhash? || witness_v0_scripthash?
        program_hex = chunks[1].unpack('H*').first
        return [Bitcoin.encode_segwit_address(0, program_hex)]
      end

      []
    end

    # get single address, or first for multisig script
    def get_address # rubocop:disable Naming/AccessorMethodName
      addrs = get_addresses
      addrs.is_a?(Array) ? addrs[0] : addrs
    end

    # generate pubkey tx script for given +pubkey+. returns a raw binary script of the form:
    #  <pubkey> OP_CHECKSIG
    def self.to_pubkey_script(pubkey)
      pack_pushdata([pubkey].pack('H*')) + [OP_CHECKSIG].pack('C')
    end

    # generate hash160 tx for given +address+. returns a raw binary script of the form:
    #  OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    def self.to_hash160_script(hash160)
      return nil unless hash160
      #  DUP   HASH160  length  hash160    EQUALVERIFY  CHECKSIG
      [['76', 'a9', '14', hash160, '88', 'ac'].join].pack('H*')
    end

    # generate p2sh output script for given +p2sh+ hash160. returns a raw binary script of the form:
    #  OP_HASH160 <p2sh> OP_EQUAL
    def self.to_p2sh_script(p2sh)
      return nil unless p2sh
      # HASH160  length  hash  EQUAL
      [['a9', '14', p2sh, '87'].join].pack('H*')
    end

    # generate pay-to-witness output script for given +witness_version+ and
    # +witness_program+. returns a raw binary script of the form:
    # <witness_version> <witness_program>
    def self.to_witness_script(witness_version, witness_program_hex)
      return nil unless (0..16).cover?(witness_version)
      return nil unless witness_program_hex
      version = witness_version != 0 ? 0x50 + witness_version : 0 # 0x50 for OP_1.. codes
      [version].pack('C') + pack_pushdata(witness_program_hex.htb)
    end

    # generate p2wpkh tx for given +address+. returns a raw binary script of the form:
    # 0 <hash160>
    def self.to_witness_hash160_script(hash160)
      return nil unless hash160
      to_witness_script(0, hash160)
    end

    # generate p2wsh output script for given +p2sh+ sha256. returns a raw binary script of the form:
    # 0 <p2sh>
    def self.to_witness_p2sh_script(p2sh)
      return nil unless p2sh
      to_witness_script(0, p2sh)
    end

    # generate hash160 or p2sh output script, depending on the type of the given +address+.
    # see #to_hash160_script and #to_p2sh_script.
    def self.to_address_script(address)
      hash160 = Bitcoin.hash160_from_address(address)
      case Bitcoin.address_type(address)
      when :hash160 then to_hash160_script(hash160)
      when :p2sh then    to_p2sh_script(hash160)
      when :witness_v0_keyhash, :witness_v0_scripthash
        witness_version, witness_program_hex = Bitcoin.decode_segwit_address(address)
        to_witness_script(witness_version, witness_program_hex)
      end
    end

    # generate multisig output script for given +pubkeys+, expecting +m+ signatures.
    # returns a raw binary script of the form:
    #  <m> <pubkey> [<pubkey> ...] <n_pubkeys> OP_CHECKMULTISIG
    def self.to_multisig_script(m, *pubkeys)
      raise 'invalid m-of-n number' unless [m, pubkeys.size].all? { |i| (0..20).cover?(i) }
      raise 'invalid m-of-n number' if pubkeys.size < m
      pubs = pubkeys.map { |pk| pack_pushdata([pk].pack('H*')) }

      m = m > 16 ?            pack_pushdata([m].pack('C'))            : [80 + m.to_i].pack('C')
      n = pubkeys.size > 16 ? pack_pushdata([pubkeys.size].pack('C')) : [80 + pubs.size].pack('C')

      [m, *pubs, n, [OP_CHECKMULTISIG].pack('C')].join
    end

    # generate OP_RETURN output script with given data. returns a raw binary script of the form:
    #  OP_RETURN <data>
    def self.to_op_return_script(data = nil)
      buf = [OP_RETURN].pack('C')
      return buf unless data
      buf + pack_pushdata([data].pack('H*'))
    end

    # generate input script sig spending a pubkey output with given +signature+ and +pubkey+.
    # returns a raw binary script sig of the form:
    #  <signature> [<pubkey>]
    def self.to_pubkey_script_sig(signature, pubkey, hash_type = SIGHASH_TYPE[:all])
      buf = pack_pushdata(signature + [hash_type].pack('C'))
      return buf unless pubkey

      expected_size = case pubkey[0]
                      when "\x04" then 65
                      when "\x02", "\x03" then 33
                      end

      raise 'pubkey is not in binary form' if !expected_size || pubkey.bytesize != expected_size

      buf + pack_pushdata(pubkey)
    end

    # generate p2sh multisig output script for given +args+.
    # returns the p2sh output script, and the redeem script needed to spend it.
    # see #to_multisig_script for the redeem script, and #to_p2sh_script for the p2sh script.
    def self.to_p2sh_multisig_script(*args)
      redeem_script = to_multisig_script(*args)
      p2sh_script = to_p2sh_script(Bitcoin.hash160(redeem_script.hth))
      [p2sh_script, redeem_script]
    end

    # alias for #to_pubkey_script_sig
    def self.to_signature_pubkey_script(*a)
      to_pubkey_script_sig(*a)
    end

    # generate input script sig spending a multisig output script.
    # returns a raw binary script sig of the form:
    #  OP_0 <sig> [<sig> ...]
    def self.to_multisig_script_sig(*sigs)
      hash_type = sigs.last.is_a?(Numeric) ? sigs.pop : SIGHASH_TYPE[:all]
      partial_script = [OP_0].pack('C*')
      sigs.reverse_each do |sig|
        partial_script = add_sig_to_multisig_script_sig(sig, partial_script, hash_type)
      end
      partial_script
    end

    # take a multisig script sig (or p2sh multisig script sig) and add
    # another signature to it after the OP_0. Used to sign a tx by
    # multiple parties. Signatures must be in the same order as the
    # pubkeys in the output script being redeemed.
    def self.add_sig_to_multisig_script_sig(sig, script_sig, hash_type = SIGHASH_TYPE[:all])
      signature = sig + [hash_type].pack('C*')
      offset = script_sig.empty? ? 0 : 1
      script_sig.insert(offset, pack_pushdata(signature))
    end

    # generate input script sig spending a p2sh-multisig output script.
    # returns a raw binary script sig of the form:
    #  OP_0 <sig> [<sig> ...] <redeem_script>
    def self.to_p2sh_multisig_script_sig(redeem_script, *sigs)
      to_multisig_script_sig(*sigs.flatten) + pack_pushdata(redeem_script)
    end

    # Sort signatures in the given +script_sig+ according to the order of pubkeys in
    # the redeem script. Also needs the +sig_hash+ to match signatures to pubkeys.
    def self.sort_p2sh_multisig_signatures(script_sig, sig_hash)
      script = new(script_sig)
      redeem_script = new(script.chunks[-1])
      pubkeys = redeem_script.get_multisig_pubkeys

      # find the pubkey for each signature by trying to verify it
      sigs = Hash[script.chunks[1...-1].map.with_index do |sig, idx|
        pubkey = pubkeys.map do |key|
          Bitcoin::Key.new(nil, key.hth).verify(sig_hash, sig) ? key : nil
        end .compact.first
        raise "Key for signature ##{idx} not found in redeem script!" unless pubkey
        [pubkey, sig]
      end]

      [OP_0].pack('C*') + pubkeys.map { |k| sigs[k] ? pack_pushdata(sigs[k]) : nil }.join +
        pack_pushdata(redeem_script.raw)
    end

    def get_signatures_required # rubocop:disable Naming/AccessorMethodName
      return false unless multisig?
      @chunks[0] - 80
    end

    def get_keys_provided # rubocop:disable Naming/AccessorMethodName
      return false unless multisig?
      @chunks[-2] - 80
    end

    def codeseparator_count
      @chunks.select { |c| c == Bitcoin::Script::OP_CODESEPARATOR }.length
    end

    # This matches CScript::GetSigOpCount(bool fAccurate)
    # Note: this does not cover P2SH script which is to be unserialized
    #       and checked explicitly when validating blocks.
    def sigops_count_accurate(is_accurate)
      count = 0
      last_opcode = nil
      @chunks.each do |chunk| # pushdate or opcode
        if [OP_CHECKSIG, OP_CHECKSIGVERIFY].include?(chunk)
          count += 1
        elsif [OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY].include?(chunk)
          # Accurate mode counts exact number of pubkeys required (not signatures, but pubkeys!).
          # Only used in P2SH scripts. Inaccurate mode counts every multisig as 20 signatures.
          count += if is_accurate && \
                      last_opcode && \
                      last_opcode.is_a?(Bitcoin::Integer) && \
                      last_opcode >= OP_1 && last_opcode <= OP_16
                     ::Bitcoin::Script.decode_OP_N(last_opcode)
                   else
                     20
                   end
        end
        last_opcode = chunk
      end
      count
    end

    # This method applies to script_sig that is an input for p2sh output.
    # Bitcoind has somewhat special way to return count for invalid input scripts:
    # it returns 0 when the opcode can't be parsed or when it's over OP_16.
    # Also, if the OP_{N} is used anywhere it's treated as 0-length data.
    # See CScript::GetSigOpCount(const CScript& scriptSig) in bitcoind.
    def sigops_count_for_p2sh
      # This is a pay-to-script-hash scriptPubKey;
      # get the last item that the scriptSig
      # pushes onto the stack:

      return 0 if @chunks.empty?

      data = nil
      @chunks.each do |chunk|
        case chunk
        when Bitcoin::Integer
          data = ''
          return 0 if chunk > OP_16
        when String
          data = chunk
        end
      end
      return 0 if data == ''

      ::Bitcoin::Script.new(data).sigops_count_accurate(true)
    end

    # Converts OP_{0,1,2,...,16} into 0, 1, 2, ..., 16.
    # Returns nil for other opcodes.
    def self.decode_OP_N(opcode) # rubocop:disable Naming/MethodName
      return 0 if opcode == OP_0
      valid_in_range = opcode.is_a?(Bitcoin::Integer) && opcode >= OP_1 && opcode <= OP_16
      opcode - (OP_1 - 1) if valid_in_range
    end

    ## OPCODES

    # Does nothing
    def op_nop; end

    def op_nop1; end

    def op_nop2; end

    def op_nop3; end

    def op_nop4; end

    def op_nop5; end

    def op_nop6; end

    def op_nop7; end

    def op_nop8; end

    def op_nop9; end

    def op_nop10; end

    # Duplicates the top stack item.
    def op_dup
      @stack << (begin
                   @stack[-1].dup
                 rescue StandardError
                   @stack[-1]
                 end)
    end

    # The input is hashed using SHA-256.
    def op_sha256
      buf = pop_string
      @stack << Digest::SHA256.digest(buf)
    end

    # The input is hashed using SHA-1.
    def op_sha1
      buf = pop_string
      @stack << Digest::SHA1.digest(buf)
    end

    # The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
    def op_hash160
      buf = pop_string
      @stack << Digest::RMD160.digest(Digest::SHA256.digest(buf))
    end

    # The input is hashed using RIPEMD-160.
    def op_ripemd160
      buf = pop_string
      @stack << Digest::RMD160.digest(buf)
    end

    # The input is hashed two times with SHA-256.
    def op_hash256
      buf = pop_string
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
      @stack[-2..-1] = [@stack[-1], *@stack[-2..-1]]
    end

    # The top two items on the stack are swapped.
    def op_swap
      @stack[-2..-1] = @stack[-2..-1].reverse if @stack[-2]
    end

    # If both a and b are not 0, the output is 1. Otherwise 0.
    def op_booland
      a, b = pop_int(2)
      @stack << ([a, b].none? { |n| n == 0 } ? 1 : 0)
    end

    # If a or b is not 0, the output is 1. Otherwise 0.
    def op_boolor
      a, b = pop_int(2)
      @stack << (a != 0 || b != 0 ? 1 : 0)
    end

    # a is added to b.
    def op_add
      a, b = pop_int(2)
      @stack << a + b
    end

    # b is subtracted from a.
    def op_sub
      a, b = pop_int(2)
      @stack << a - b
    end

    # Returns 1 if a is less than b, 0 otherwise.
    def op_lessthan
      a, b = pop_int(2)
      @stack << (a < b ? 1 : 0)
    end

    # Returns 1 if a is less than or equal to b, 0 otherwise.
    def op_lessthanorequal
      a, b = pop_int(2)
      @stack << (a <= b ? 1 : 0)
    end

    # Returns 1 if a is greater than b, 0 otherwise.
    def op_greaterthan
      a, b = pop_int(2)
      @stack << (a > b ? 1 : 0)
    end

    # Returns 1 if a is greater than or equal to b, 0 otherwise.
    def op_greaterthanorequal
      a, b = pop_int(2)
      @stack << (a >= b ? 1 : 0)
    end

    # If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    def op_not
      a = pop_int
      @stack << (a == 0 ? 1 : 0)
    end

    def op_0notequal
      a = pop_int
      @stack << (a != 0 ? 1 : 0)
    end

    # The input is made positive.
    def op_abs
      a = pop_int
      @stack << a.abs
    end

    # The input is divided by 2. Currently disabled.
    def op_2div
      a = pop_int
      @stack << (a >> 1)
    end

    # The input is multiplied by 2. Currently disabled.
    def op_2mul
      a = pop_int
      @stack << (a << 1)
    end

    # 1 is added to the input.
    def op_1add
      a = pop_int
      @stack << (a + 1)
    end

    # 1 is subtracted from the input.
    def op_1sub
      a = pop_int
      @stack << (a - 1)
    end

    # The sign of the input is flipped.
    def op_negate
      a = pop_int
      @stack << -a
    end

    # Removes the top stack item.
    def op_drop
      @stack.pop
    end

    # Returns 1 if the inputs are exactly equal, 0 otherwise.
    def op_equal
      a, b = pop_string(2)
      @stack << (a == b ? 1 : 0)
    end

    # Marks transaction as invalid if top stack value is not true.
    # True is removed, but false is not.
    def op_verify
      res = pop_int
      if cast_to_bool(res) == false
        @stack << res
        @script_invalid = true # raise 'transaction invalid' ?
      else
        @script_invalid = false
      end
    end

    # Same as OP_EQUAL, but runs OP_VERIFY afterward.
    def op_equalverify
      op_equal
      op_verify
    end

    # An empty array of bytes is pushed onto the stack.
    def op_0
      @stack << '' # []
    end

    # The number 1 is pushed onto the stack. Same as OP_TRUE
    def op_1
      @stack << 1
    end

    # Returns the smaller of a and b.
    def op_min
      @stack << pop_int(2).min
    end

    # Returns the larger of a and b.
    def op_max
      @stack << pop_int(2).max
    end

    # Copies the pair of items two spaces back in the stack to the front.
    def op_2over
      @stack << @stack[-4]
      @stack << @stack[-4]
    end

    # Swaps the top two pairs of items.
    def op_2swap
      p1 = @stack.pop(2)
      p2 = @stack.pop(2)
      @stack += p1 + p2
    end

    # If the input is true, duplicate it.
    def op_ifdup
      @stack << @stack.last if cast_to_bool(@stack.last) == true
    end

    # The number -1 is pushed onto the stack.
    def op_1negate
      @stack << -1
    end

    # Puts the number of stack items onto the stack.
    def op_depth
      @stack << @stack.size
    end

    # Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
    def op_within
      bn1, bn2, bn3 = pop_int(3)
      @stack << (bn2 <= bn1 && bn1 < bn3 ? 1 : 0)
    end

    # Returns 1 if the numbers are equal, 0 otherwise.
    def op_numequal
      a, b = pop_int(2)
      @stack << (a == b ? 1 : 0)
    end

    # Returns 1 if the numbers are not equal, 0 otherwise.
    def op_numnotequal
      a, b = pop_int(2)
      @stack << (a != b ? 1 : 0)
    end

    # Marks transaction as invalid.
    def op_return
      @script_invalid = true
      nil
    end

    # Copies the second-to-top stack item to the top.
    def op_over
      item = @stack[-2]
      @stack << item if item
    end

    # If the top stack value is not 0, the statements are executed. The top stack value is removed.
    def op_if
      value = false
      if @do_exec
        if @stack.empty?
          invalid
          return
        end
        value = cast_to_bool(pop_string) != false
      end
      @exec_stack << value
    end

    # If the top stack value is 0, the statements are executed. The top stack value is removed.
    def op_notif
      value = false
      if @do_exec
        if @stack.empty?
          invalid
          return
        end
        value = cast_to_bool(pop_string) == false
      end
      @exec_stack << value
    end

    # If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and
    # if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
    def op_else
      return if @exec_stack.empty?
      @exec_stack[-1] = !@exec_stack[-1]
    end

    # Ends an if/else block.
    def op_endif
      return if @exec_stack.empty?
      @exec_stack.pop
    end

    # The item n back in the stack is copied to the top.
    def op_pick
      return invalid if @stack.size < 2
      pos = pop_int
      return invalid if (pos < 0) || (pos >= @stack.size)
      item = @stack[-(pos + 1)]
      @stack << item if item
    end

    # The fifth and sixth items back are moved to the top of the stack.
    def op_2rot
      return invalid if @stack.size < 6
      @stack[-6..-1] = [*@stack[-4..-1], *@stack[-6..-5]]
    end

    # The item n back in the stack is moved to the top.
    def op_roll
      return invalid if @stack.size < 2
      pos = pop_int
      return invalid if (pos < 0) || (pos >= @stack.size)
      idx = -(pos + 1)
      item = @stack[idx]
      @stack.delete_at(idx) if item
      @stack << item if item
    end

    # The top three items on the stack are rotated to the left.
    def op_rot
      return if @stack.size < 3
      @stack[-3..-1] = [@stack[-2], @stack[-1], @stack[-3]]
    end

    # Removes the top two stack items.
    def op_2drop
      @stack.pop(2)
    end

    # Duplicates the top two stack items.
    def op_2dup
      @stack.push(*@stack[-2..-1])
    end

    # Duplicates the top three stack items.
    def op_3dup
      @stack.push(*@stack[-3..-1])
    end

    # Removes the second-to-top stack item.
    def op_nip
      @stack.delete_at(-2)
    end

    # Returns the length of the input string.
    def op_size
      item = @stack[-1]
      size = case item
             when String then item.bytesize
             when Numeric then OpenSSL::BN.new(item.to_s).to_mpi.size - 4
             end
      @stack << size
    end

    # Transaction is invalid unless occuring in an unexecuted OP_IF branch
    def op_ver
      invalid if @do_exec
    end

    def pop_int(count = nil)
      return cast_to_bignum(@stack.pop) unless count
      @stack.pop(count).map { |i| cast_to_bignum(i) }
    end

    def pop_string(count = nil)
      return cast_to_string(@stack.pop) unless count
      @stack.pop(count).map { |i| cast_to_string(i) }
    end

    def cast_to_bignum(buf)
      unless buf
        invalid
        return 0
      end

      case buf
      when Numeric
        invalid if OpenSSL::BN.new(buf.to_s).to_s(0).unpack('N')[0] > 4
        buf
      when String
        invalid if buf.bytesize > 4
        OpenSSL::BN.new([buf.bytesize].pack('N') + buf.reverse, 0).to_i
      else
        raise TypeError, format(
          'cast_to_bignum: failed to cast: %<buf>s (%<buf_class>s)', buf: buf, buf_class: buf.class
        )
      end
    end

    def cast_to_string(buf)
      unless buf
        invalid
        return ''
      end

      case buf
      when Numeric then OpenSSL::BN.new(buf.to_s).to_s(0)[4..-1].reverse
      when String then buf
      else
        raise TypeError, format(
          'cast_to_string: failed to cast: %<buf>s (%<buf_class>s)', buf: buf, buf_class: buf.class
        )
      end
    end

    def cast_to_bool(buf)
      buf = cast_to_string(buf).unpack('C*')
      size = buf.size
      buf.each.with_index do |byte, index|
        if byte != 0
          # Can be negative zero
          return false if (index == (size - 1)) && byte == 0x80
          return true
        end
      end
      false
    end

    # Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    def op_numequalverify
      op_numequal
      op_verify
    end

    # All of the signature checking words will only match signatures
    # to the data after the most recently-executed OP_CODESEPARATOR.
    def op_codeseparator
      @codehash_start = @chunks.size - @chunks.reverse.index(OP_CODESEPARATOR)
      @last_codeseparator_index = @chunk_last_index
    end

    def codehash_script(opcode)
      # CScript scriptCode(pbegincodehash, pend);
      script = to_string(
        @chunks[(@codehash_start || 0)...@chunks.size - @chunks.reverse.index(opcode)]
      )
      checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack('H*')[0])
      [script, checkhash]
    end

    # do a CHECKSIG operation on the current stack,
    # asking +check_callback+ to do the actual signature verification.
    # This is used by Protocol::Tx#verify_input_signature
    def op_checksig(check_callback, opts = {})
      return invalid if @stack.size < 2
      pubkey = cast_to_string(@stack.pop)
      return (@stack << 0) unless Bitcoin::Script.check_pubkey_encoding?(pubkey, opts)
      drop_sigs = [cast_to_string(@stack[-1])]

      signature = cast_to_string(@stack.pop)
      return invalid unless Bitcoin::Script.check_signature_encoding?(signature, opts)
      return (@stack << 0) if signature == ''

      sig, hash_type = parse_sig(signature)

      subscript = sighash_subscript(drop_sigs, opts)

      @stack << if check_callback.nil? # for tests
                  1
                else # real signature check callback
                  (check_callback.call(pubkey, sig, hash_type, subscript) == true ? 1 : 0)
                end
    end

    def sighash_subscript(drop_sigs, opts = {})
      if opts[:fork_id]
        drop_sigs.reject! do |signature|
          if signature && !signature.empty?
            _, hash_type = parse_sig(signature)
            (hash_type & SIGHASH_TYPE[:forkid]) != 0
          end
        end
      end

      if inner_p2sh? && @inner_script_code
        ::Bitcoin::Script.new(@inner_script_code).to_binary_without_signatures(drop_sigs)
      else
        to_binary_without_signatures(drop_sigs)
      end
    end

    # Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
    def op_checksigverify(check_callback, opts = {})
      op_checksig(check_callback, opts)
      op_verify
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
    # see https://github.com/bitcoin/bitcoin/blob/master/src/script.cpp#L931
    #
    # TODO: validate signature order
    # TODO: take global opcode count
    # rubocop:disable Metrics/CyclomaticComplexity
    # rubocop:disable Metrics/PerceivedComplexity
    def op_checkmultisig(check_callback, opts = {})
      return invalid if @stack.empty?
      n_pubkeys = pop_int
      return invalid unless (0..20).cover?(n_pubkeys)
      # return invalid  if (nOpCount += n_pubkeys) > 201
      return invalid if @stack.size < n_pubkeys
      pubkeys = pop_string(n_pubkeys)

      return invalid if @stack.empty?
      n_sigs = pop_int
      return invalid if n_sigs < 0 || n_sigs > n_pubkeys
      return invalid if @stack.size < n_sigs
      sigs = pop_string(n_sigs)
      drop_sigs = sigs.dup

      # Bitcoin-core removes an extra item from the stack
      @stack.pop

      subscript = sighash_subscript(drop_sigs, opts)

      success = true
      while success && n_sigs > 0
        sig = sigs.pop
        pub = pubkeys.pop
        return (@stack << 0) unless Bitcoin::Script.check_pubkey_encoding?(pub, opts)
        return invalid unless Bitcoin::Script.check_signature_encoding?(sig, opts)
        unless sig && !sig.empty?
          success = false
          break
        end
        signature, hash_type = parse_sig(sig)
        if !pub.empty? && check_callback.call(pub, signature, hash_type, subscript)
          n_sigs -= 1
        else
          sigs << sig
        end
        n_pubkeys -= 1
        success = false if n_sigs > n_pubkeys
      end

      @stack << (success ? 1 : 0)
    end
    # rubocop:enable Metrics/CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity

    # Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
    def op_checkmultisigverify(check_callback, opts = {})
      op_checkmultisig(check_callback, opts)
      op_verify
    end

    OPCODES_METHOD = Hash[*instance_methods.grep(/^op_/).map do |m|
                            [(begin
                                OPCODES.find { |_k, v| v == m.to_s.upcase }.first
                              rescue StandardError
                                nil
                              end), m]
                          end.flatten]
    OPCODES_METHOD[0]  = :op_0
    OPCODES_METHOD[81] = :op_1

    def self.check_pubkey_encoding?(pubkey, opts = {})
      return false if opts[:verify_strictenc] && !compressed_or_uncompressed_pub_key?(pubkey)
      true
    end

    def self.compressed_or_uncompressed_pub_key?(pubkey)
      return false if pubkey.bytesize < 33 # "Non-canonical public key: too short"
      case pubkey[0]
      when "\x04"
        # "Non-canonical public key: invalid length for uncompressed key"
        return false if pubkey.bytesize != 65
      when "\x02", "\x03"
        # "Non-canonical public key: invalid length for compressed key"
        return false if pubkey.bytesize != 33
      else
        return false # "Non-canonical public key: compressed nor uncompressed"
      end
      true
    end

    # Loosely matches CheckSignatureEncoding()
    # rubocop:disable Metrics/CyclomaticComplexity
    # rubocop:disable Metrics/PerceivedComplexity
    def self.check_signature_encoding?(sig, opts = {})
      return true if sig.bytesize == 0

      if (
          opts[:verify_dersig] ||
          opts[:verify_low_s] ||
          opts[:verify_strictenc]
        ) && !der_signature?(sig)
        return false
      end
      return false if opts[:verify_low_s] && !low_der_signature?(sig)

      if opts[:verify_strictenc]
        return false unless defined_hashtype_signature?(sig)

        hash_type = sig.unpack('C*')[-1]
        uses_forkid = (hash_type & SIGHASH_TYPE[:forkid]) != 0
        return false if opts[:fork_id] && !uses_forkid
        return false if !opts[:fork_id] && uses_forkid
      end

      true
    end

    # Loosely correlates with IsDERSignature() from interpreter.cpp
    def self.der_signature?(sig)
      return false if sig.bytesize < 9 # Non-canonical signature: too short
      return false if sig.bytesize > 73 # Non-canonical signature: too long

      s = sig.unpack('C*')

      return false if s[0] != 0x30 # Non-canonical signature: wrong type
      return false if s[1] != s.size - 3 # Non-canonical signature: wrong length marker

      length_r = s[3]
      return false if (5 + length_r) >= s.size # Non-canonical signature: S length misplaced
      length_s = s[5 + length_r]

      # Non-canonical signature: R+S length mismatch
      return false if (length_r + length_s + 7) != s.size

      return false if s[2] != 0x02 # Non-canonical signature: R value type mismatch

      return false if length_r == 0 # Non-canonical signature: R length is zero

      r_val = s.slice(4, length_r)
      return false if r_val[0] & 0x80 != 0 # Non-canonical signature: R value negative

      # Non-canonical signature: R value excessively padded
      return false if length_r > 1 && (r_val[0] == 0x00) && r_val[1] & 0x80 == 0

      s_val = s.slice(6 + length_r, length_s)
      return false if s[6 + length_r - 2] != 0x02 # Non-canonical signature: S value type mismatch

      return false if length_s == 0 # Non-canonical signature: S length is zero
      return false if (s_val[0] & 0x80) != 0 # Non-canonical signature: S value negative

      # Non-canonical signature: S value excessively padded
      return false if length_s > 1 && (s_val[0] == 0x00) && !(s_val[1] & 0x80)

      true
    end
    # rubocop:enable Metrics/CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity

    # Compares two arrays of bytes
    def self.compare_big_endian(c1, c2)
      c1 = c1.dup
      c2 = c2.dup # Clone the arrays

      # rubocop:disable Style/NestedModifier
      return 1 if c1.shift > 0 while c1.size > c2.size
      return -1 if c2.shift > 0 while c2.size > c1.size
      # rubocop:enable Style/NestedModifier

      c1.size.times { |idx| return c1[idx] - c2[idx] if c1[idx] != c2[idx] }
      0
    end

    # Loosely correlates with IsLowDERSignature() from interpreter.cpp
    def self.low_der_signature?(sig)
      s = sig.unpack('C*')

      length_r = s[3]
      length_s = s[5 + length_r]
      s_val = s.slice(6 + length_r, length_s)

      # If the S value is above the order of the curve divided by two, its
      # complement modulo the order could have been used instead, which is
      # one byte shorter when encoded correctly.
      max_mod_half_order = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0
      ]

      compare_big_endian(s_val, [0]) > 0 &&
        compare_big_endian(s_val, max_mod_half_order) <= 0
    end

    def self.defined_hashtype_signature?(sig)
      return false if sig.empty?

      s = sig.unpack('C*')
      hash_type = s[-1] & ~(SIGHASH_TYPE[:anyonecanpay] | SIGHASH_TYPE[:forkid])

      # Non-canonical signature: unknown hashtype byte
      return false if hash_type < SIGHASH_TYPE[:all] || hash_type > SIGHASH_TYPE[:single]

      true
    end

    def self.define_deprecated_predicate_method(method_name, class_method: false)
      deprecated_name = format('is_%<method_name>s?', method_name: method_name)
      new_name = format('%<method_name>s?', method_name: method_name)

      definer = class_method ? method(:define_singleton_method) : method(:define_method)
      definer.call(deprecated_name) do |*args|
        warn format('[DEPRECATION] Script.%<deprecated_name>s is deprecated. ' \
                    'Use %<new_name>s instead.',
                    deprecated_name: deprecated_name,
                    new_name: new_name)

        method = method(new_name)
        if method.arity == 1
          method.call(*args)
        else
          method.call
        end
      end
    end

    # Instance methods
    %i[
      pay_to_script_hash
      standard
      pubkey
      hash160
      multisig
      op_return
      witness
      witness_v0_keyhash
      witness_v0_scripthash
      push_only
    ].each do |method_name|
      define_deprecated_predicate_method(method_name)
    end
    alias is_send_to_ip? is_pubkey?
    alias send_to_ip? pubkey?
    alias is_p2sh? is_pay_to_script_hash?
    alias p2sh? pay_to_script_hash?

    # Class methods
    %i[
      compressed_or_uncompressed_pub_key
      der_signature
      low_der_signature
      defined_hashtype_signature
    ].each do |method_name|
      define_deprecated_predicate_method(method_name, class_method: true)
    end

    private

    def parse_sig(sig)
      hash_type = sig[-1].unpack('C')[0]
      sig = sig[0...-1]
      [sig, hash_type]
    end
  end
end
