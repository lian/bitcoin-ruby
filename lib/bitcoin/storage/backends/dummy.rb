module Bitcoin::Storage::Backends
  class Dummy < Base
    
    attr_accessor :blk, :tx
    
    def initialize *args
      @blk = []
      @tx = {}
      super *args
    end
    
    def reset
      @blk = []
      @tx = {}
    end

    def get_depth
      @blk.size - 1
    end
    
    def get_head
      @blk[-1].hash
    end
    
    def store_block(blk)
      return nil  unless blk
      
      if block = get_block_by_hash(blk.hash)
        log.info { "ALREADY STORED" }
      end
      
      prev_block = get_block_by_hash(Bitcoin::hth(blk.prev_block.reverse))
      
      unless prev_block
        unless blk.hash == Bitcoin.network[:genesis_hash]
          log.warn { "INVALID BLOCK: #{blk.hash}" }
          return nil
        end
      end

      blk.tx.each {|tx| store_tx(tx) }
      @blk << blk

      
      log.info { "NEW HEAD: #{blk.hash} DEPTH: #{get_depth}" }
      
      get_depth
    end
    
    def get_block_by_depth(depth)
      @blk[depth]
    end
    
    def get_block_by_hash(blk_hash)
      @blk.find {|blk| blk.hash == blk_hash}
    end

    def get_block_depth(blk_hash)
      @blk.index(get_block_by_hash(blk_hash)) || -1
    end
    
    def store_tx(tx)
      @tx[tx.hash] = tx
      true
    end
    
    def get_tx(tx_hash)
      @tx[tx_hash]
    end
    
  end
  
end
