require 'bitcoin'

module Bitcoin
  class Script
    OP_PUSHDATA1   = 76
    OP_PUSHDATA2   = 77
    OP_PUSHDATA4   = 78
    OP_DUP         = 118
    OP_HASH160     = 169
    OP_EQUALVERIFY = 136
    OP_CHECKSIG    = 172
    OP_CHECKSIGVERIFY      = 173
    OP_CHECKMULTISIG       = 174
    OP_CHECKMULTISIGVERIFY = 175

    def self.join(a, b)
    end

    attr_reader :raw, :chunks

    def initialize(bytes, offset=0)
      @stack, @raw = [], bytes
      @chunks = parse(bytes, offset)
    end

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
          len = progam.shift(1)[0]
          chunks << program.shift(len).pack("C*")
        elsif (opcode == OP_PUSHDATA2)
          len = progam.shift(2).pack("C*").unpack("n")[0]
          chunks << program.shift(len).pack("C*")
        elsif (opcode == OP_PUSHDATA4)
          len = progam.shift(4).pack("C*").unpack("N")[0]
          chunks << program.shift(len).pack("C*")
        else
          chunks << opcode
        end
      end
      chunks
    end

    def to_string
      @chunks.map{|i|
        case i
        when Fixnum
          case i
          when OP_DUP;         "OP_DUP"
          when OP_HASH160;     "OP_HASH160"
          when OP_CHECKSIG;    "OP_CHECKSIG"
          when OP_EQUALVERIFY; "OP_EQUALVERIFY"
          when OP_CHECKSIGVERIFY;      "OP_CHECKSIGVERIFY"
          when OP_CHECKMULTISIG;       "OP_CHECKMULTISIG"
          when OP_CHECKMULTISIGVERIFY; "OP_CHECKMULTISIGVERIFY"
          else "(opcode #{i})"
          end
        when String
          i.unpack("H*")[0]
        end
      }.join(" ")
    end

    def self.binary_from_string(script_string)
      script_string.split(" ").map{|i|
        case i
          when "OP_DUP";         OP_DUP
          when "OP_HASH160";     OP_HASH160
          when "OP_CHECKSIG";    OP_CHECKSIG
          when "OP_EQUALVERIFY"; OP_EQUALVERIFY
          when "OP_CHECKSIGVERIFY";      OP_CHECKSIGVERIFY
          when "OP_CHECKMULTISIG";       OP_CHECKMULTISIG
          when "OP_CHECKMULTISIGVERIFY"; OP_CHECKMULTISIGVERIFY
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

    def run(&check_callback)
      @chunks.each{|chunk|
        case chunk
        when Fixnum
          case chunk
          when OP_DUP
            @stack << @stack[-1].dup
          when OP_HASH160
            buf = @stack.pop
            @stack << Digest::RMD160.digest(Digest::SHA256.digest(buf))
          when OP_CHECKSIG
            op_checksig(check_callback)
          when OP_EQUALVERIFY
            a, b = @stack.pop(2).reverse
            return :EQUALVERIFY_FAILED if a != b
          when OP_CHECKSIGVERIFY
            raise "opcode OP_CHECKSIGVERIFY not implemented yet."
          when OP_CHECKMULTISIG
            raise "opcode OP_CHECKMULTISIG not implemented yet."
          when OP_CHECKMULTISIGVERIFY
            raise "opcode OP_CHECKMULTISIGVERIFY not implemented yet."
          else raise "opcode #{i} unkown or not implemented"
          end
        when String
          @stack << chunk
        end
      }
      @stack.pop == true
    end

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

    def is_send_to_ip?
      return false if @chunks.size != 2
      (@chunks[1] == OP_CHECKSIG) && @chunks[0].size > 1
    end

    def get_pubkey
      return @chunks[0].unpack("H*")[0] if @chunks.size == 1
      if @chunks.size != 2
        raise "Script not right size for scriptSig, expecting 2 but got #{@chunks.size}"
      end
      if !@chunks[1].is_a?(Fixnum) && @chunks[0].bytesize > 1
        raise "Script not in the standard scriptSig form"
      end
      @chunks[0].unpack("H*")[0]
    end

    def get_pubkey_address
      Bitcoin.pubkey_to_address(get_pubkey)
    end

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
