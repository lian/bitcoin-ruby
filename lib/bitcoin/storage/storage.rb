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
      def self.#{name} config, *args
        Backends.const_get("#{name.capitalize}Store").new(config, *args)
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

      # main branch (longest valid chain)
      MAIN = 0

      # side branch (connected, valid, but too short)
      SIDE = 1

      # orphan branch (not connected to main branch / genesis block)
      ORPHAN = 2

      attr_reader :log

      def initialize(config = {}, getblocks_callback = nil)
        @config = config
        @getblocks_callback = getblocks_callback
        @log    = config[:log] || Bitcoin::Storage.log
      end

      # reset the store; delete all data
      def reset
        raise "Not implemented"
      end

      # store given block +blk+.
      # determine branch/chain and dept of block. trigger reorg if side branch becomes longer
      # than current main chain and connect orpans.
      def store_block blk
        log.debug { "new block #{blk.hash}" }

        existing = get_block(blk.hash)
        return [existing.depth, existing.chain]  if existing && existing.chain == MAIN

        prev_block = get_block(hth(blk.prev_block.reverse))
        if !prev_block || prev_block.chain == ORPHAN
          if blk.hash == Bitcoin.network[:genesis_hash]
            log.debug { "=> genesis (0)" }
            return persist_block(blk, MAIN, 0)
          else
            depth = prev_block ? prev_block.depth + 1 : 0
            log.debug { "=> orphan (#{depth})" }
            return persist_block(blk, ORPHAN, depth)
          end
        end
        depth = prev_block.depth + 1
        if prev_block.chain == MAIN
          next_block = prev_block.get_next_block
          if next_block && next_block.chain == MAIN
            log.debug { "=> side (#{depth})" }
            return persist_block(blk, SIDE, depth)
          else
            log.debug { "=> main (#{depth})" }
            return persist_block(blk, MAIN, depth)
          end
        else
          head = get_head
          if prev_block.depth + 1 <= head.depth
            log.debug { "=> side (#{depth})" }
            return persist_block(blk, SIDE, depth)
          else
            log.debug { "=> reorg" }
            new_main, new_side = [], []
            fork_block = prev_block
            while fork_block.chain != MAIN
              new_main << fork_block.hash
              fork_block = fork_block.get_prev_block
            end
            b = fork_block
            while b = b.get_next_block
              new_side << b.hash
            end
            log.debug { "new main: #{new_main.inspect}" }
            log.debug { "new side: #{new_side.inspect}" }
            update_blocks([[new_main, {:chain => MAIN}], [new_side, {:chain => SIDE}]])
            return persist_block(blk, MAIN, depth)
          end
        end
      end

      # persist given block +blk+ to storage.
      def persist_block(blk)
        raise "Not implemented"
      end

      # update +attrs+ for block with given +hash+.
      # typically used to update chain.
      def update_block(hash, attrs)
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
      def get_locator pointer = get_head
        return [Bitcoin::hth("\x00"*32)]  if get_depth == -1
        locator = []
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
      def get_txouts_for_address(address, unconfirmed = false)
        hash160 = Bitcoin.hash160_from_address(address)
        get_txouts_for_hash160(hash160, unconfirmed)
      end

      # get balance for given +hash160+
      def get_balance(hash160, unconfirmed = false)
        txouts = get_txouts_for_hash160(hash160, unconfirmed)
        unspent = txouts.select {|o| o.get_next_in.nil?}
        unspent.map(&:value).inject {|a,b| a+=b; a} || 0
      rescue
        nil
      end

      # import satoshi bitcoind blk0001.dat blockchain file
      def import filename, max_depth = nil
        File.open(filename) do |file|
          until file.eof?
            magic = file.read(4)
            raise "invalid network magic"  unless Bitcoin.network[:magic_head] == magic
            size = file.read(4).unpack("L")[0]
            blk = Bitcoin::P::Block.new(file.read(size))
            depth, chain = store_block(blk)
            break  if max_depth && depth >= max_depth
          end
        end
      end
    end
  end
end
