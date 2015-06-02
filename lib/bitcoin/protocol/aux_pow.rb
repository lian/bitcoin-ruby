# encoding: ascii-8bit

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
        buf = StringIO.new(data)
        parse_data_from_io(buf)
        buf.eof? ? '' : buf.read
      end

      def parse_data_from_io(data)
        @tx = P::Tx.new(nil)
        @tx.parse_data_from_io(data)

        @block_hash = data.read(32)
        branch_count = P.unpack_var_int_from_io(data)
        @branch = []
        branch_count.times{
          break if data.eof?
          @branch << data.read(32)
        }
        @mrkl_index = data.read(4).unpack("I")[0]

        @aux_branch = []
        aux_branch_count = P.unpack_var_int_from_io(data)
        aux_branch_count.times{
          break if data.eof?
          @aux_branch << data.read(32)
        }

        @aux_index = data.read(4).unpack("I")[0]
        block = data.read(80)
        @parent_block = P::Block.new(block)

        data
      end


      def to_payload
        payload = @tx.to_payload
        payload << @block_hash
        payload << P.pack_var_int(@branch.count)
        payload << @branch.join
        payload << [@mrkl_index].pack("I")
        payload << P.pack_var_int(@aux_branch.count)
        payload << @aux_branch.join
        payload << [@aux_index].pack("I")
        payload << @parent_block.to_payload
        payload
      end

      def self.from_hash h
        aux_pow = new(nil)
        aux_pow.instance_eval do
          @tx = P::Tx.from_hash(h['tx'])
          @block_hash = h['block_hash'].htb
          @branch = h['branch'].map(&:htb)
          @mrkl_index = h['mrkl_index']
          @aux_branch = h['aux_branch'].map(&:htb)
          @aux_index = h['aux_index']
          @parent_block = P::Block.from_hash(h['parent_block'])
        end
        aux_pow
      end

      def to_hash
        { 'tx' => @tx.to_hash,
          'block_hash' => @block_hash.hth,
          'branch' => @branch.map(&:hth),
          'mrkl_index' => @mrkl_index,
          'aux_branch' => @aux_branch.map(&:hth),
          'aux_index' => @aux_index,
          'parent_block' => @parent_block.to_hash }
      end

    end

  end
end
