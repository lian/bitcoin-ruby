module Bitcoin::Storage

  class BlockChain

    def self.depth
      Block.order("depth DESC").limit(1).first.depth
    end

    def self.head
      hth(Block.order("depth DESC").limit(1).first.block_hash)
    rescue
      Bitcoin::network[:genesis_block]
    end

    def self.locator
      log.info { "Computing blockchain locator" }
      locator = []
      pointer = head
      step = 1
      while pointer && pointer != Bitcoin::network[:genesis_block]
        log.debug { "blochain locator pointer: #{pointer}" }
        locator << pointer
        block = Block.get(pointer) rescue nil
        break unless block
        depth = block.depth - step
        break unless depth > 0
        prev_block = Block.where(:depth => depth)[0] # TODO
        break unless prev_block
        pointer = hth(prev_block.block_hash)
        step *= 2  if locator.size > 10
      end
      locator << Bitcoin::network[:genesis_block]
      locator
    end

    def self.add_block(blk)
      return nil  unless blk
      if block = Block.get(blk.hash)
        log.debug { "Block #{blk.hash} already stored" }
        return nil
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




    def self.balance(pubkey_hash)
      s = "41" + pubkey_hash + "ac"
      Output.where("script = decode('#{s}', 'hex')")
    end





  end

end
