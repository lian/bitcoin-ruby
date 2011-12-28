require 'active_record'

$:.unshift( File.dirname(__FILE__) )

module Bitcoin::Storage::Backends

  class ActiverecordStore < StoreBase
    
    require_relative 'activerecord_store/base'
    require_relative 'activerecord_store/block'
    require_relative 'activerecord_store/transactions_parent'
    require_relative 'activerecord_store/transaction'
    require_relative 'activerecord_store/input'
    require_relative 'activerecord_store/output'

    include Bitcoin::Storage::Backends::ActiverecordStore

    def initialize config
      @config = config
      connect
      super @config
    end

    def connect
      # TODO: load schema if not already there
      ActiveRecord::Base.establish_connection @config
      if defined?(Log4r)
        ActiveRecord::Base.logger = Bitcoin::Logger.create(:database)
        ActiveRecord::Base.logger.level = 2
      end
    end

    def reset
      [:blocks, :transactions_parents, :transactions, :inputs, :outputs, :chains].each do |t|
        ActiveRecord::Base.connection.query("DELETE from #{t};")
      end
    end

    def get_depth
      Block.order("depth DESC").limit(1).first.depth rescue -1
    end
    
    def get_head
      Bitcoin::hth(Block.order("depth DESC").limit(1).first.block_hash)
    rescue
      Bitcoin::network[:genesis_hash]
    end
    
    # TODO
    def get_balance
      s = "41" + pubkey_hash + "ac"
      Output.where("script = decode('#{s}', 'hex')")
     end
    
    def store_block(blk)
      return nil  unless blk

      if block = get_block(blk.hash)
        log.debug { "Block #{blk.hash} already stored" }
      end

      block = Block.from_protocol(blk)

      return nil  unless block

      begin
        if block.save
          log.info { "NEW HEAD: #{blk.hash} (#{blk.payload.size} bytes) - DEPTH: #{block.depth}" }
          return block.depth
        end
      rescue
        log.error { "ERROR SAVING BLOCK: #{$!.inspect}" }
        p $@.first
        puts *$@
        binding.pry
        exit
      end

    end

    def get_block(blk_hash)
      Block.where("block_hash = decode(?, 'hex')", blk_hash).first.to_protocol rescue nil
    end

    def get_block_by_depth(depth)
      Block.where(:depth => depth).first.to_protocol rescue nil
    end

    def get_block_depth(blk_hash)
      block = Block.where("block_hash = decode(?, 'hex')", blk_hash).first
      block.depth
    end

    def store_tx(tx)
      return nil  unless tx
      
      if transaction = get_tx(tx.hash)
        log.debug { "Tx #{tx.hash} already stored"}
        return false
      end

      transaction = Transaction.from_protocol(tx)

      begin
        if transaction.save
          log.info { "Tx #{tx.hash} saved" }
          return true
        else
          log.warn { "Error saving tx #{tx.hash}" }
          return false
        end
      rescue
        log.error { "Exception trying to save tx: #{$!.message}" }
        return false
      end
    end

    def get_tx(tx_hash)
      tx = Transaction.where("transaction_hash = decode('#{tx_hash}', 'hex')").first
      return nil unless tx
      tx.to_protocol
    end

  end


  module StorageModel

    def log
      Bitcoin::Storage::log
    end

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end
    
    def bts data
      connection.escape_bytea(data)
    end

  end

  ActiverecordStore.constants.each do |c|
    const = ActiverecordStore.const_get(c)
    const.extend(StorageModel)
  end

end
