# encoding: ascii-8bit

module Bitcoin
  module Protocol
    # Auxiliary Proof-of-Work for merge-mined blockchains
    # See https://en.bitcoin.it/wiki/Merged_mining_specification.
    #
    # The AuxPow contains all data needed to verify that the child
    # block was included in the parents coinbase transaction, and
    # the parent satisfies the difficulty target.
    #
    # It encodes the +parent_block+ header, and its +coinbase_tx+.
    # The +coinbase_branch+ and +coinbase_index+ can be used to recalculate
    # the parent blocks merkle root and prove the coinbase transaction is
    # really included in it.
    # The +chain_branch+ and +chain_index+ are used to link the child block
    # to the merkle root contained in the +coinbase_tx+. (So there can be
    # more than one merge-mined chain)
    #
    # TODO: decode merged-mining data from +coinbase_tx+
    class AuxPow
      # Coinbase transaction of the parent block, linking to the child block
      attr_accessor :coinbase_tx

      # Hash of the parent block header
      attr_accessor :block_hash

      # Merkle branch linking the +coinbase_tx+ to the +parent_block+
      attr_accessor :coinbase_branch

      # Index of the +coinbase_tx+ in the parent blocks merkle tree
      attr_accessor :coinbase_index

      # Merkle branch linking the child block to the +coinbase_tx+
      attr_accessor :chain_branch

      # Index of the child block in the chain merkle tree
      attr_accessor :chain_index

      # Parent block header
      attr_accessor :parent_block

      def initialize(data)
        parse_data data if data
      end

      def parse_data(data)
        buf = StringIO.new(data)
        parse_data_from_io(buf)
        buf.eof? ? '' : buf.read
      end

      def parse_data_from_io(data)
        @coinbase_tx = P::Tx.new(nil)
        @coinbase_tx.parse_data_from_io(data)

        @block_hash = data.read(32)
        coinbase_branch_count = P.unpack_var_int_from_io(data)

        @coinbase_branch = []
        coinbase_branch_count.times do
          break if data.eof?
          @coinbase_branch << data.read(32).reverse.hth
        end

        @coinbase_index = data.read(4).unpack('I')[0]

        @chain_branch = []
        chain_branch_count = P.unpack_var_int_from_io(data)
        chain_branch_count.times do
          break if data.eof?
          @chain_branch << data.read(32).reverse.hth
        end

        @chain_index = data.read(4).unpack('I')[0]
        block = data.read(80)
        @parent_block = P::Block.new(block)

        data
      end

      def to_payload
        payload = @coinbase_tx.to_payload
        payload << @block_hash
        payload << P.pack_var_int(@coinbase_branch.count)
        payload << @coinbase_branch.map(&:htb).map(&:reverse).join
        payload << [@coinbase_index].pack('I')
        payload << P.pack_var_int(@chain_branch.count)
        payload << @chain_branch.map(&:htb).map(&:reverse).join
        payload << [@chain_index].pack('I')
        payload << @parent_block.to_payload
        payload
      end

      def self.from_hash(h)
        aux_pow = new(nil)
        aux_pow.instance_eval do
          @coinbase_tx = P::Tx.from_hash(h['coinbase_tx'])
          @block_hash = h['block_hash'].htb
          @coinbase_branch = h['coinbase_branch']
          @coinbase_index = h['coinbase_index']
          @chain_branch = h['chain_branch']
          @chain_index = h['chain_index']
          @parent_block = P::Block.from_hash(h['parent_block'])
        end
        aux_pow
      end

      def to_hash
        { 'coinbase_tx' => @coinbase_tx.to_hash,
          'block_hash' => @block_hash.hth,
          'coinbase_branch' => @coinbase_branch,
          'coinbase_index' => @coinbase_index,
          'chain_branch' => @chain_branch,
          'chain_index' => @chain_index,
          'parent_block' => @parent_block.to_hash }
      end
    end
  end
end
