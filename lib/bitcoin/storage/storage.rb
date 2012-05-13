# The storage implementation supports different backends, which inherit from
# Storage::StoreBase and implement the same interface.
# Each backend returns Storage::Models objects to easily access helper methods and metadata.
#
# The most stable backend is Backends::SequelStore, which uses sequel and can use all
# kinds of SQL database backends.
module Bitcoin::Storage

  autoload :Models, 'bitcoin/storage/models'

  @log = Bitcoin::Logger.create(:storage)
  def self.log; @log; end

  BACKENDS = [:dummy, :sequel]
  BACKENDS.each do |name|
    module_eval <<-EOS
      def self.#{name} config
        Backends.const_get("#{name.capitalize}Store").new(config)
      end
    EOS
  end

  module Backends

    BACKENDS.each {|b| autoload("#{b.to_s.capitalize}Store", "bitcoin/storage/#{b}") }

    # Base class for storage backends.
    # Every backend must overwrite the "Not implemented" methods
    # and provide an implementation specific to the storage.
    # Also, before returning the objects, they should be wrapped
    # inside the appropriate Bitcoin::Storage::Models class.
    class StoreBase

      attr_reader :log

      def initialize(config = {})
        @config = config
        @log    = config[:log] || Bitcoin::Storage.log
      end

      # reset the store; delete all data
      def reset
        raise "Not implemented"
      end

      # store given +block+
      def store_block(blk)
        raise "Not implemented"
      end

      # store given +tx+
      def store_tx(tx)
        raise "Not implemented"
      end

      # check if block with given +blk_hash+ is already stored
      def has_block(blk_hash)
        raise "Not implemented"
      end

      # check if tx with given +tx_hash+ is already stored
      def has_tx(tx_hash)
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
        while pointer && pointer.hash != Bitcoin::network[:genesis_hash]
          locator << pointer.hash
          depth = pointer.depth - step
          break unless depth > 0
          prev_block = get_block_by_depth(depth) # TODO
          break unless prev_block
          pointer = prev_block
          step *= 2  if locator.size > 10
        end
        locator << Bitcoin::network[:genesis_hash]
        locator
      end

      # get block with given +blk_hash+
      def get_block(blk_hash)
        raise "Not implemented"
      end

      # get block with given +depth+ from main chain
      def get_block_by_depth(depth)
        raise "Not implemented"
      end

      # get block with given +prev_hash+
      def get_block_by_prev_hash(prev_hash)
        raise "Not implemented"
      end

      # get block that includes tx with given +tx_hash+
      def get_block_by_tx(tx_hash)
        raise "Not implemented"
      end

      # get block by given +block_id+
      def get_block_by_id(block_id)
        raise "Not implemented"
      end

      # get corresponding txin for the txout in
      # transaction +tx_hash+ with index +txout_idx+
      def get_txin_for_txout(tx_hash, txout_idx)
        raise "Not implemented"
      end

      # get tx with given +tx_hash+
      def get_tx(tx_hash)
        raise "Not implemented"
      end

      # get tx with given +tx_id+
      def get_tx_by_id(tx_id)
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
        hash160 = Bitcoin.hash160_from_address(address)
        get_txouts_for_hash160(hash160)
      end

      # get balance for given +hash160+
      def get_balance(hash160)
        txouts = get_txouts_for_hash160(hash160)
        confirmed = txouts.select {|o| !!o.get_tx.get_block}
        unspent = confirmed.select {|o| o.get_next_in.nil?}
        unspent.map(&:value).inject {|a,b| a+=b; a} || 0
      rescue
        nil
      end

    end
  end
end
