# encoding: ascii-8bit

# StorageModels defines objects that are returned from storage.
# These objects inherit from their Bitcoin::Protocol counterpart
# and add some additional data and methods.
#
# * Bitcoin::Storage::Models::Block
# * Bitcoin::Storage::Models::Tx
# * Bitcoin::Storage::Models::TxIn
# * Bitcoin::Storage::Models::TxOut
module Bitcoin::Storage::Models

  # Block retrieved from storage. (see Bitcoin::Protocol::Block)
  class Block < Bitcoin::Protocol::Block

    attr_accessor :ver, :prev_block, :mrkl_root, :time, :bits, :nonce, :tx
    attr_reader :store, :id, :depth, :chain, :work, :size

    def initialize store, data
      @store = store
      @id = data[:id]
      @depth = data[:depth]
      @chain = data[:chain]
      @work = data[:work]
      @size = data[:size]
      @tx = []
    end

    # get the block this one builds upon
    def get_prev_block
      @store.get_block(@prev_block.reverse_hth)
    end

    # get the block that builds upon this one
    def get_next_block
      @store.get_block_by_prev_hash(@hash)
    end

    def total_out
      @total_out ||= tx.inject(0){ |m,t| m + t.total_out }
    end

    def total_in
      @total_in ||= tx.inject(0){ |m,t| m + t.total_in }
    end

    def total_fee
      @total_fee ||= tx.inject(0){ |m,t| m + t.fee }
    end
  end

  # Transaction retrieved from storage. (see Bitcoin::Protocol::Tx)
  class Tx < Bitcoin::Protocol::Tx

    attr_accessor :ver, :lock_time, :hash
    attr_reader :store, :id, :blk_id, :size, :idx

    def initialize store, data
      @store = store
      @id = data[:id]
      @blk_id = data[:blk_id]
      @size = data[:size]
      @idx  = data[:idx]
      super(nil)
    end

    # get the block this transaction is in
    def get_block
      return nil  unless @blk_id
      @block ||= @store.get_block_by_id(@blk_id)
    end

    # get the number of blocks that confirm this tx in the main chain
    def confirmations
      return 0  unless get_block
      @store.get_head.depth - get_block.depth + 1
    end

    def total_out
      @total_out ||= self.out.inject(0){ |e, o| e + o.value }
    end

    # if tx_in is coinbase, set in value as total_out, fee could be 0
    def total_in
      @total_in ||= self.in.inject(0){ |m, input|
        m + (input.coinbase? ? total_out : (input.get_prev_out.try(:value) || 0))
      }
    end

    def fee
      @fee ||= total_in - total_out
    end
  end

  # Transaction input retrieved from storage. (see Bitcoin::Protocol::TxIn
  class TxIn < Bitcoin::Protocol::TxIn

    attr_reader :store, :id, :tx_id, :tx_idx

    def initialize store, data
      @store = store
      @id = data[:id]
      @tx_id = data[:tx_id]
      @tx_idx = data[:tx_idx]
    end

    # get the transaction this input is in
    def get_tx
      @tx ||= @store.get_tx_by_id(@tx_id)
    end

    # get the previous output referenced by this input
    def get_prev_out
      @prev_tx_out ||= begin
        prev_tx = @store.get_tx(@prev_out.reverse_hth)
        return nil  unless prev_tx
        prev_tx.out[@prev_out_index]
      end
    end

  end

  # Transaction output retrieved from storage. (see Bitcoin::Protocol::TxOut)
  class TxOut < Bitcoin::Protocol::TxOut

    attr_reader :store, :id, :tx_id, :tx_idx, :type

    def initialize store, data
      @store = store
      @id = data[:id]
      @tx_id = data[:tx_id]
      @tx_idx = data[:tx_idx]
      @type = data[:type]
    end

    def hash160
      script.get_hash160
    end

    # get the transaction this output is in
    def get_tx
      @tx ||= @store.get_tx_by_id(@tx_id)
    end

    # get the next input that references this output
    def get_next_in
      @store.get_txin_for_txout(get_tx.hash, @tx_idx)
    rescue
      nil
    end

    # get all addresses this txout corresponds to (if possible)
    def get_address
      script.get_address
    end

    # get the single address this txout corresponds to (first for multisig tx)
    def get_addresses
      script.get_addresses
    end

    def get_namecoin_name
      @store.get_name_by_txout_id(@id)
    end

    def type
      script.type
    end

    def script
      @_script = Bitcoin::Script.new(@pk_script)
    end

  end

end
