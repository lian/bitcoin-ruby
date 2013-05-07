module Bitcoin
  module Protocol

    # Auxiliary Proof-of-Work for merge-mined blockchains
    class AuxPow

      # Coinbase transaction linking the aux to its parent block
      attr_accessor :tx

      # Hash of the block header
      attr_accessor :block_hash

      # Merkle branches to bring the transaction to the block's merkle root
      attr_accessor :branch

      # Index of this transaction in the merkle tree
      attr_accessor :mrkl_index

      # Merkle branches linking this aux chains to the aux root
      attr_accessor :aux_branch

      # Index of "this" block chain in the aux chain list
      attr_accessor :aux_index

      # Parent block header
      attr_accessor :parent_block

      def initialize(data)
        parse_data (data) if data
      end

      def parse_data(data)
        @tx = P::Tx.new(nil)
        payload = @tx.parse_data(data)

        @block_hash, payload = payload.unpack("a32a*")
        branch_count, payload = P.unpack_var_int(payload)
        @branch = []
        branch_count.times {
          b, payload = payload.unpack("a32a*")
          @branch << b
        }
        @mrkl_index, payload = payload.unpack("Ia*")

        @aux_branch = []
        aux_branch_count, payload = P.unpack_var_int(payload)
        aux_branch_count.times {
          b, payload = payload.unpack("a32a*")
          @aux_branch << b
        }

        @aux_index, payload = payload.unpack("Ia*")
        block, payload = payload.unpack("a80a*")
        @parent_block = P::Block.new(block)

        payload
      end

    end

  end
end
