require 'bitcoin'

class Bitcoin::Script

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
  OP_CHECKHASHVERIFY = 177
  OP_CODESEPARATOR = 171
  OP_MIN          = 163
  OP_MAX          = 164
  OP_2OVER        = 112
  OP_2SWAP        = 114
  OP_IFDUP        = 115
  OP_DEPTH        = 116
  OP_1NEGATE      = 79
  # OP_IF           = 99
  # OP_NOTIF        = 100
  # OP_ELSE         = 103
  # OP_ENDIF        = 104

  OPCODES = Hash[*constants.grep(/^OP_/).map{|i| [const_get(i), i.to_s] }.flatten]
  OPCODES[0] = "0"
  OPCODES[81] = "1"

  OPCODES_ALIAS = {
    "OP_TRUE"  => OP_1,
    "OP_FALSE" => OP_0,
    "OP_NOP1" => OP_EVAL,
    "OP_NOP2" => OP_CHECKHASHVERIFY
  }

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
  def to_string(chunks=nil)
    (chunks || @chunks).map{|i|
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

  class ScriptOpcodeError < StandardError; end

  # raw script binary of a string representation
  def self.binary_from_string(script_string)
    script_string.split(" ").map{|i|
      case i
      when /^OP_PUSHDATA[124]$/;     # skip
      when *OPCODES.values;          OPCODES.find{|k,v| v == i }.first
      when *OPCODES_ALIAS.keys;      OPCODES_ALIAS.find{|k,v| k == i }.last
      when /^([2-9]|1[0-6])$/;       OP_2_16[$1.to_i-2]
      when /\(opcode (\d+)\)/;       $1.to_i
      when /OP_(.+)$/;               raise ScriptOpcodeError, "#{i} not defined!"
      else 
        data = [i].pack("H*")
        size = data.bytesize

        head = if size < OP_PUSHDATA1
                 [size].pack("C")
               elsif size > OP_PUSHDATA1 && size <= 0xff
                 [OP_PUSHDATA1, size].pack("CC")
               elsif size > 0xff && size <= 0xffff
                 [OP_PUSHDATA2, size].pack("Cv")
               elsif size > 0xffff && size <= 0xffffffff
                 [OP_PUSHDATA4, size].pack("CV")
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

  # run the script. +check_callback+ is called for OP_CHECKSIG operations
  def run(&check_callback)
    return pay_to_script_hash(check_callback)  if is_p2sh?
    @debug = []
    @chunks.each{|chunk|
      break if invalid?
      @debug << @stack.map{|i| i.unpack("H*") rescue i}
      
      case chunk
      when Fixnum
        case chunk

        when *OPCODES_METHOD.keys
          m = method( n=OPCODES_METHOD[chunk] )
          @debug << n.to_s.upcase
          (m.arity == 1) ? m.call(check_callback) : m.call  # invoke opcode method

        when *OP_2_16
          @stack << OP_2_16.index(chunk) + 2
          @debug << "OP_#{chunk-80}"
        else
          name = OPCODES[chunk] || chunk
          raise "opcode #{name} unkown or not implemented"
        end
      when String
        @debug << "PUSH DATA #{chunk.unpack("H*")[0]}"
        @stack << chunk
      end
    }
    @debug << @stack.map{|i| i.unpack("H*") rescue i }

    if @script_invalid
      @stack << 0
      @debug << "INVALID TRANSACTION"
    end

    @debug << "RESULT"
    return false if @stack.empty?
    return false if @stack.pop == 0
    true
  end

  def invalid
    @script_invalid = true; nil
  end

  def codehash_script(opcode)
    # CScript scriptCode(pbegincodehash, pend);
    script    = to_string(@chunks[(@codehash_start||0)...@chunks.size-@chunks.reverse.index(opcode)])
    checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
    [script, checkhash]
  end

  def self.drop_signatures(script_pubkey, drop_signatures)
    script = new(script_pubkey).to_string.split(" ").delete_if{|c| drop_signatures.include?(c) }.join(" ")
    script_pubkey = binary_from_string(script)
  end

  # pay_to_script_hash: https://en.bitcoin.it/wiki/BIP_0016
  #
  # <sig> {<pub> OP_CHECKSIG} | OP_HASH160 <script_hash> OP_EQUAL
  def pay_to_script_hash(check_callback)
    return false  unless @chunks.size == 5
    script_hash = @chunks[-2]
    script = @chunks[-4]
    sig = self.class.from_string(@chunks[0].unpack("H*")[0]).raw

    return false unless Bitcoin.hash160(script.unpack("H*")[0]) == script_hash.unpack("H*")[0]
    script = self.class.new(sig + script)
    script.run(&check_callback)
  end

  def is_pay_to_script_hash?
    @chunks.size >= 3 && @chunks[-3] == OP_HASH160 &&
      @chunks[-2].bytesize == 20 && @chunks[-1] == OP_EQUAL
  end
  alias :is_p2sh? :is_pay_to_script_hash?

  # check if script is in one of the recognized standard formats
  def is_standard?
    is_pubkey? || is_hash160? || is_multisig? || is_p2sh?
  end

  # is this a pubkey tx
  def is_pubkey?
    return false if @chunks.size != 2
    (@chunks[1] == OP_CHECKSIG) && @chunks[0].size > 1
  end
  alias :is_send_to_ip? :is_pubkey?

  # is this a hash160 (address) tx
  def is_hash160?
    return false  if @chunks.size != 5
    (@chunks[0..1] + @chunks[-2..-1]) ==
      [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] &&
      @chunks[2].is_a?(String) && @chunks[2].bytesize == 20
  end

  # is this a multisig tx
  def is_multisig?
    return false  if @chunks.size > 6 || @chunks.size < 4
    @chunks[-1] == OP_CHECKMULTISIG
  end

  def type
       if is_hash160?;   :hash160
    elsif is_pubkey?;    :pubkey
    elsif is_multisig?;  :multisig
    elsif is_p2sh?;      :p2sh
    else;                :unknown
    end
  end

  # get the public key for this pubkey script
  def get_pubkey
    return @chunks[0].unpack("H*")[0] if @chunks.size == 1
    is_pubkey? ? @chunks[0].unpack("H*")[0] : nil
  end

  # get the pubkey address for this pubkey script
  def get_pubkey_address
    Bitcoin.pubkey_to_address(get_pubkey)
  end

  # get the hash160 for this hash160 script
  def get_hash160
    return @chunks[2..-3][0].unpack("H*")[0]  if is_hash160?
    return Bitcoin.hash160(get_pubkey)        if is_pubkey?
  end

  # get the hash160 address for this hash160 script
  def get_hash160_address
    Bitcoin.hash160_to_address(get_hash160)
  end

  # get the public keys for this multisig script
  def get_multisig_pubkeys
    1.upto(@chunks[-2] - 80).map {|i| @chunks[i]}
  end

  # get the pubkey addresses for this multisig script
  def get_multisig_addresses
    get_multisig_pubkeys.map {|p| Bitcoin::Key.new(nil, p.unpack("H*")[0]).addr}
  end

  # get all addresses this script corresponds to (if possible)
  def get_addresses
    return [get_pubkey_address]  if is_pubkey?
    return [get_hash160_address] if is_hash160?
    return get_multisig_addresses  if is_multisig?
  end

  # get single address, or first for multisig script
  def get_address
    addrs = get_addresses
    addrs.is_a?(Array) ? addrs[0] : addrs
  end

  # generate pubkey tx script for given +pubkey+
  def self.to_pubkey_script(pubkey)
    pk = [pubkey].pack("H*")
    [[pk.bytesize].pack("C"), pk, "\xAC"].join
  end

  # generate hash160 tx for given +address+
  def self.to_hash160_script(hash160)
    return nil  unless hash160
    #  DUP   HASH160  length  hash160    EQUALVERIFY  CHECKSIG
    [ ["76", "a9",    "14",   hash160,   "88",        "ac"].join ].pack("H*")
  end

  def self.to_p2sh_script(p2sh)
    return nil  unless p2sh
    # HASH160  length  hash  EQUAL
    [ ["a9",   "14",   p2sh, "87"].join ].pack("H*")
  end

  def self.to_address_script(address)
    hash160 = Bitcoin.hash160_from_address(address)
    case Bitcoin.address_type(address)
    when :hash160; to_hash160_script(hash160)
    when :p2sh;    to_p2sh_script(hash160)
    end
  end

  # generate multisig tx for given +pubkeys+, expecting +m+ signatures
  def self.to_multisig_script(m, *pubkeys)
    pubs = pubkeys.map{|pk|p=[pk].pack("H*"); [p.bytesize].pack("C") + p}
    [ [80 + m.to_i].pack("C"), *pubs, [80 + pubs.size].pack("C"), "\xAE"].join
  end

  # generate pubkey script sig for given +signature+ and +pubkey+
  def self.to_pubkey_script_sig(signature, pubkey)
    hash_type = "\x01"
    #pubkey = [pubkey].pack("H*") if pubkey.bytesize != 65
    raise "pubkey is not in binary form" unless pubkey.bytesize == 65  && pubkey[0] == "\x04"
    [ [signature.bytesize+1].pack("C"), signature, hash_type, [pubkey.bytesize].pack("C"), pubkey ].join
  end

  # alias for #to_pubkey_script_sig
  def self.to_signature_pubkey_script(*a)
    to_pubkey_script_sig(*a)
  end

  def self.to_multisig_script_sig(*sigs)
    from_string("0 #{sigs.map{|s|s.unpack('H*')[0]}.join(' ')}").raw
  end

  def get_signatures_required
    return false unless is_multisig?
    @chunks[0] - 80
  end

  ## OPCODES

  # Does nothing
  def op_nop
  end

  # Duplicates the top stack item.
  def op_dup
    @stack << (@stack[-1].dup rescue @stack[-1])
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
    if res == 0
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

  # The number 1 is pushed onto the stack. Same as OP_TRUE
  def op_1
    @stack << 1
  end

  # Returns the smaller of a and b.
  def op_min
    @stack << @stack.pop(2).min
  end

  # Returns the larger of a and b.
  def op_max
    @stack << @stack.pop(2).max
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
    @stack += p1 += p2
  end
  
  # If the input is true, duplicate it.
  def op_ifdup
    if @stack.last != 0
      @stack << @stack.last
    end
  end

  # The number -1 is pushed onto the stack.
  def op_1negate
    @stack << -1
  end
  
  # Puts the number of stack items onto the stack.
  def op_depth
    @stack << @stack.size
  end

  # https://en.bitcoin.it/wiki/BIP_0017  (old OP_NOP2)
  # TODO: don't rely on it yet. add guards from wikipage too.
  def op_checkhashverify
    unless @checkhash && (@checkhash == @stack[-1].unpack("H*")[0])
      @script_invalid = true
    end
  end

  # All of the signature checking words will only match signatures
  # to the data after the most recently-executed OP_CODESEPARATOR.
  def op_codeseparator
    @codehash_start = @chunks.size - @chunks.reverse.index(OP_CODESEPARATOR)
  end

  # do a CHECKSIG operation on the current stack,
  # asking +check_callback+ to do the actual signature verification.
  # This is used by Protocol::Tx#verify_input_signature
  def op_checksig(check_callback)
    return invalid if @stack.size < 2
    pubkey = @stack.pop
    drop_sigs      = [@stack[-1].unpack("H*")[0]]
    sig, hash_type = parse_sig(@stack.pop)

    if @chunks.include?(OP_CHECKHASHVERIFY)
      # Subset of script starting at the most recent codeseparator to OP_CHECKSIG
      script_code, @checkhash = codehash_script(OP_CHECKSIG)
    else
      script_code, drop_sigs = nil, nil
    end

    if check_callback == nil # for tests
      @stack << 1
    else # real signature check callback
      @stack <<
        ((check_callback.call(pubkey, sig, hash_type, drop_sigs, script_code) == true) ? 1 : 0)
    end
  end

  def op_checksigverify(check_callback)
    op_checksig(check_callback)
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
  def op_checkmultisig(check_callback)
    n_pubkeys = @stack.pop
    return invalid  unless (0..20).include?(n_pubkeys)
    return invalid  unless @stack.last(n_pubkeys).all?{|e| e.is_a?(String) && e != '' }
    #return invalid  if ((@op_count ||= 0) += n_pubkeys) > 201
    pubkeys = @stack.pop(n_pubkeys)

    n_sigs = @stack.pop
    return invalid  unless (0..n_pubkeys).include?(n_sigs)
    return invalid  unless @stack.last(n_sigs).all?{|e| e.is_a?(String) && e != '' }
    sigs = (drop_sigs = @stack.pop(n_sigs)).map{|s| parse_sig(s) }

    @stack.pop if @stack[-1] == '' # remove OP_NOP from stack

    if @chunks.include?(OP_CHECKHASHVERIFY)
      # Subset of script starting at the most recent codeseparator to OP_CHECKMULTISIG
      script_code, @checkhash = codehash_script(OP_CHECKMULTISIG)
      drop_sigs.map!{|i| i.unpack("H*")[0] }
    else
      script_code, drop_sigs = nil, nil
    end

    valid_sigs = 0
    sigs.each{|sig, hash_type| pubkeys.each{|pubkey|
        valid_sigs += 1  if check_callback.call(pubkey, sig, hash_type, drop_sigs, script_code)
      }}

    @stack << ((valid_sigs == n_sigs) ? 1 : (invalid; 0))
  end

  OPCODES_METHOD = Hash[*instance_methods.grep(/^op_/).map{|m|
      [ (OPCODES.find{|k,v| v == m.to_s.upcase }.first rescue nil), m ]
    }.flatten]
  OPCODES_METHOD[0]  = :op_0
  OPCODES_METHOD[81] = :op_1

  private

  def parse_sig(sig)
    hash_type = sig[-1].unpack("C")[0]
    sig = sig[0...-1]
    return sig, hash_type
  end
end
