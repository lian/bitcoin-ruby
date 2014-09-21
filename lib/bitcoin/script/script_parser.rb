module Bitcoin
  class Script
    class ScriptParser < Struct.new(:bytes, :offset)
      attr_accessor :chunks

      def parse
        self.chunks = []
        until program.empty?
          opcode = program.shift

          case opcode
            when 1...Bitcoin::Script::OP_PUSHDATA1 then push_data_0 opcode
            when Bitcoin::Script::OP_PUSHDATA1 then push_data_1
            when Bitcoin::Script::OP_PUSHDATA2 then push_data_2
            when Bitcoin::Script::OP_PUSHDATA4 then push_data_4
            else
              chunks << opcode
          end
        end
      rescue => ex
        # bail out! #run returns false but serialization roundtrips still create the right payload.
        chunks.pop if ex.message.include?('invalid OP_PUSHDATA')
        shovel_invalid_pushdata
        raise ex
      end

      def program
        @program ||= bytes.unpack("C*")
      end

      def push_data_0(opcode)
        len, tmp = opcode, program[0]
        shovel_from_program_to_chunks(len)

        # 0x16 = 22 due to OP_2_16 from_string parsing
        if len == 1 && tmp && tmp <= 22
          chunks.last.bitcoin_pushdata = Bitcoin::Script::OP_PUSHDATA0
          chunks.last.bitcoin_pushdata_length = len
        else
          raise_if_invalid_op('OP_PUSHDATA0', len)
        end
      end

      def shovel_from_program_to_chunks(len)
        chunks << program.shift(len).pack("C*")
      end

      def raise_if_invalid_op(optype, len)
        if len != chunks.last.bytesize
          raise "invalid #{optype}"
        end
      end

      def push_data_1
        push_data min_length: Bitcoin::Script::OP_PUSHDATA1 + 1,
                  max_length: 0xff,
                  op_type: 'OP_PUSHDATA1',
                  shift_length: 1
      end

      def push_data(options)
        shift_length = options.fetch(:shift_length)
        max_acceptable_length = options.fetch(:max_length) { nil }
        min_acceptable_length = options.fetch(:min_length)
        op_type = options.fetch(:op_type)

        len = shift_for_length shift_length
        shovel_from_program_to_chunks(len)

        if max_acceptable_length.nil?
          if len > min_acceptable_length
            raise_if_invalid_op(op_type, len)
          end
        else
          if (min_acceptable_length..max_acceptable_length) === len
            raise_if_invalid_op(op_type, len)
          end
        end

        chunks.last.bitcoin_pushdata = Bitcoin::Script::OPCODES.invert[op_type]
        chunks.last.bitcoin_pushdata_length = len
      end

      def shift_for_length(bytes_to_shift)
        shifted = program.shift(bytes_to_shift)
        return shifted[0] if bytes_to_shift == 1

        packed = shifted.pack('C*')
        return packed.unpack("v")[0] if bytes_to_shift == 2
        packed.unpack("V")[0] if bytes_to_shift == 4
      end

      def push_data_2
        push_data min_length: 0xff + 1,
                  max_length: 0xffff,
                  op_type: 'OP_PUSHDATA2',
                  shift_length: 2
      end

      def push_data_4
        push_data min_length: 0xffff + 1,
                  op_type: 'OP_PUSHDATA4',
                  shift_length: 4
      end

      def shovel_invalid_pushdata
        c = bytes.unpack('C*').pack('C*')
        c.bitcoin_pushdata = Bitcoin::Script::OP_PUSHDATA_INVALID
        c.bitcoin_pushdata_length = c.bytesize
        chunks << c
      end
    end
  end
end