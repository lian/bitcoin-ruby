module Bitcoin::Storage

  @log = Bitcoin::Logger.create("storage")
  def self.log; @log; end

  module Backends
    autoload :Dummy,        "bitcoin/storage/backends/dummy"
    autoload :Activerecord, "bitcoin/storage/backends/activerecord"

    class Base

      def initialize(config = {})
        @config = config
        @log    = config[:log] || Bitcoin::Storage.log
      end

      # get the storage logger
      def log; @log; end

      # reset the store; delete all data
      def reset
        raise "Not implemented"
      end

      # get the hash of the leading block
      def get_head
        raise "Not implemented"
      end

      # return depth of the head block
      def get_depth
        raise "Not implemented"
      end

      # compute blockchain locator
      def get_locator
        return [Bitcoin::hth("\x00"*32)]  if get_depth == -1
        locator = []
        pointer = get_head
        step = 1
        while pointer && pointer != Bitcoin::network[:genesis_hash]
          locator << pointer
          depth = get_block_depth(pointer) - step
          break unless depth > 0
          prev_block = get_block_by_depth(depth) # TODO
          break unless prev_block
          pointer = prev_block.hash
          step *= 2  if locator.size > 10
        end
        locator << Bitcoin::network[:genesis_hash]
        locator
      end

      # store given +block+
      def store_block(blk)
        raise "Not implemented"
      end

      # get block with given +blk_hash+
      def get_block(blk_hash)
        raise "Not implemented"
      end

      # get block with given +depth+ from main chain
      def get_block_by_depth(depth)
        raise "Not implemented"
      end

      # get depth for block with given +blk_hash+
      def get_block_depth(blk_hash)
        raise "not implemented"
      end

      # store given +tx+
      def store_tx(tx)
        raise "Not implemented"
      end

      # get tx with given +tx_hash+
      def get_tx(tx_hash)
        raise "Not implemented"
      end

    end
  end
end
