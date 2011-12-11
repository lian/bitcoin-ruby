module Bitcoin::Storage

  @log = Bitcoin::Logger.create("storage")
  def self.log; @log; end

  BACKENDS = [:dummy, :sequel, :activerecord]
  BACKENDS.each do |name|
    module_eval <<-EOS
      def self.#{name} config
        Backends.const_get("#{name.capitalize}Store").new(config)
      end
    EOS
  end

  module Backends

    BACKENDS.each {|b| autoload("#{b.to_s.capitalize}Store", "bitcoin/storage/#{b}") }

    class StoreBase

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

      # collect all txouts containing the
      # given +script+
      def get_txouts_for_pk_script(script)
        raise "Not implemented"
      end

      # collect all txouts containing a
      # standard tx to given +address+
      def get_txouts_for_address(address)
        script = Bitcoin::Script.to_address_script(address)
        get_txouts_for_pk_script(script)
      end

      # get balance for given +address+
      def get_balance(address)
        txouts = get_txouts_for_address(address)
        unspent = txouts.select {|o| o.get_next_in.nil?}
        unspent.map(&:value).inject {|a,b| a+=b; a} || 0
      rescue
        nil
      end

    end
  end
end
