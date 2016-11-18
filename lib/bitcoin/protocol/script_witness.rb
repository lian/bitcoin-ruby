# encoding: ascii-8bit

module Bitcoin

  module Protocol

    class ScriptWitness

      # witness stack
      attr_reader :stack

      def initialize
        @stack = []
      end

      # check empty
      def empty?
        stack.empty?
      end

      # output script in raw binary format
      def to_payload
        payload = Bitcoin::Protocol.pack_var_int(stack.size)
        stack.each{|e|
          payload << Bitcoin::Protocol.pack_var_int(e.htb.bytesize)
          payload << e.htb
        }
        payload
      end

    end

  end

end