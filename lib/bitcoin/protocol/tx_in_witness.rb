# encoding: ascii-8bit

module Bitcoin

  module Protocol

    class TxInWitness
      attr_reader :script_witness

      def initialize
        @script_witness = Bitcoin::Protocol::ScriptWitness.new
      end

      # add witness script to stack
      def add_stack(script)
        script_witness.stack << script
      end

      #  output witness script in raw binary format with witness
      def to_payload
        script_witness.to_payload
      end

      # get witness script stack
      def stack
        script_witness.stack
      end

    end

  end
end