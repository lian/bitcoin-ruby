# encoding: ascii-8bit
require 'json'

Bitcoin.require_dependency :leveldb


module Bitcoin::Storage::Backends

  # Storage backend using Sequel to connect to arbitrary SQL databases.
  # Inherits from StoreBase and implements its interface.
  class SpvStore < StoreBase

    # sequel database connection
    attr_accessor :db

    DEFAULT_CONFIG = { mode: :full, cache_head: false }

    # create sequel store with given +config+
    def initialize config, *args
      super config, *args
      @blocks = {}
      @last_block = nil
    end

    # connect to database
    def init_store_connection
      @db = LevelDB::DB.new @config[:db]
      log.info { "Opened LevelDB #{@config[:db]}" }
    end

    # reset database; delete all data
    def reset
      @db.close
      `rm -rf #{@config[:db]}`
      @db = LevelDB::DB.new @config[:db]
      @head = nil
    end

    def add_watched_address addr, depth = 0
      return nil  if watched_addrs(depth.to_i).include?(addr)
      @watched_addrs = (JSON.load(@db["watched_addrs"]) || [])
      @watched_addrs << [addr, depth.to_i]
      @db["watched_addrs"] = @watched_addrs.to_json
      log.info { "Added watched address #{addr}, now watching #{@watched_addrs.count}." }
      super(addr, depth.to_i)
      @watched_addrs.count
    end

    def watched_addrs depth
      @watched_addrs ||= (JSON.load(@db["watched_addrs"]) || [])
      @watched_addrs.map {|a, d| a  if (d || 0) <= depth.to_i }.compact
    end

    def watch_addrs? depth = 0
      watched_addrs(depth).any? || @config[:watch_all_addrs]
    end

    # persist given block +blk+ to storage.
    def persist_block blk, chain, depth, prev_work = 0

      blk = Bitcoin::P::MerkleBlock.from_block(blk, true)  unless blk.is_a?(Bitcoin::P::MerkleBlock)
      work = prev_work + blk.block_work

      # make sure blk.to_payload is only the header and no tx data
      tx = blk.tx; blk.tx = []

      key = chain == 2 ? "o#{blk.hash.htb}" : "b#{blk.hash.htb}"
      @db[key] = blk_to_disk(blk.to_payload, chain, depth, work)
      if chain == MAIN
        @head = wrap_block(blk, chain, depth, work)
        @db["head"] = blk.hash.htb
        @db["d#{depth}"] = blk.hash.htb
      end

      tx.each.with_index {|tx, idx| store_tx(tx, true, blk, idx) }  if watch_addrs?(depth)

      if !@last_block || @last_block.to_i < Time.now.to_i - 10
        # connect orphans
        @db.each(from: "o", to: "p") do |hash, data|
          orphan = wrap_block(*blk_from_disk(data))
          if orphan.prev_block.reverse.hth == blk.hash
            begin
              store_block(orphan)
            rescue SystemStackError
              EM.defer { store_block(orphan) }  if EM.reactor_running?
            end
          end
        end
      end
      @last_block = Time.now

      return depth, chain
    end

    def blk_to_disk payload, chain, depth, work
      work_s = work.to_s
      [Bitcoin::P.pack_var_int(chain), Bitcoin::P.pack_var_int(depth), Bitcoin::P.pack_var_int(work_s.size), work_s, payload].join
    end

    def blk_from_disk data
      chain, data = Bitcoin::P.unpack_var_int(data)
      depth, data = Bitcoin::P.unpack_var_int(data)
      work_size, data = Bitcoin::P.unpack_var_int(data)
      work = data[0..work_size].to_i
      return Bitcoin::P::MerkleBlock.new(data[work_size..-1]), chain, depth, work
    end

    def reorg new_side, new_main
      new_side.each do |hash|
        blk = Bitcoin::P::MerkleBlock.from_disk(@db["b#{hash.htb}"])
        blk.chain = 1
        @db["b#{hash.htb}"] = blk.to_disk
      end

      new_main.each do |hash|
        blk = Bitcoin::P::MerkleBlock.from_disk(@db["b#{hash.htb}"])
        blk.chain = 0
        @db["b#{hash.htb}"] = blk.to_disk
        @db["d#{blk.depth}"] = hash.htb
      end
    end

    # store transaction +tx+
    def store_tx(tx, validate = true, block = nil, idx = nil)
      return  unless watched_addrs = watched_addrs(block ? block.depth : @head.depth)

      relevant = false
      # TODO optimize
      tx.out.each.with_index {|o,i|
        address = o.parsed_script.get_address
        relevant = true  if @config[:watch_all_addrs] || watched_addrs.include?(address)
      }
      tx.in.each {|i|
        next  unless prev_tx = get_tx(i.prev_out.reverse_hth)
        next  unless prev_out = prev_tx.out[i.prev_out_index]
        relevant = true  if @config[:watch_all_addrs] ||
        (prev_out.parsed_script.get_addresses & watched_addrs).any?
      }
      return  unless relevant

      @log.debug { "Storing tx #{tx.hash} (#{tx.to_payload.bytesize} bytes)" }
      @db["t#{tx.hash.htb}"] = tx.payload
    end

    # check if block +blk_hash+ exists
    def has_block(blk_hash)
      !!@db["b#{blk_hash.htb}"]
    end

    # check if transaction +tx_hash+ exists
    def has_tx(tx_hash)
      !!@db["t#{tx_hash.htb}"]
    end

    # get head block (highest block from the MAIN chain)
    def get_head
      return  unless hash = @db["head"]
      @head ||= wrap_block(*blk_from_disk(@db["b#{hash}"]))
    end

    def get_head_hash
      @db["head"].hth
    end

    # get depth of MAIN chain
    def get_depth
      get_head.depth rescue -1
    end

    # get block for given +blk_hash+
    def get_block(blk_hash)
      if (head = get_head) && head.hash == blk_hash
        return head
      end
      return nil  unless data = @db["b#{blk_hash.htb}"]
      wrap_block(*blk_from_disk(data))
    end

    # get block by given +depth+
    def get_block_by_depth(depth)
      get_block(@db["d#{depth}"].hth)
    end

    # get block by given +prev_hash+
    def get_block_by_prev_hash(prev_hash)
      return  unless prev_blk = get_block(prev_hash)
      return  unless blk_hash = @db["d#{prev_blk.depth + 1}"]
      get_block(blk_hash.hth)
    end

    # get transaction for given +tx_hash+
    def get_tx(tx_hash)
      return  nil  unless data = @db["t#{tx_hash.htb}"]
      wrap_tx(Bitcoin::P::Tx.new(data))
    end

    # get all Models::TxOut matching given +hash160+
    def get_txouts_for_hash160(hash160, unconfirmed = false)
      txouts = []
      @db.each(from: "t", to: "u") do |hash, attrs|
        tx = wrap_tx(Bitcoin::P::Tx.new(attrs))
        tx.out.each.with_index do |txout, idx|
          script = Bitcoin::Script.new(txout.pk_script)
          if script.get_addresses.include?(Bitcoin.hash160_to_address(hash160))
            txouts << wrap_txout(txout, tx.hash, idx, script)
          end
        end
      end
      # TODO: select confirmed
      txouts
    end

    # wrap given +block+ into Models::Block
    def wrap_block(block, chain, depth, work)
      return nil  unless block

      data = { id: depth, depth: depth, chain: chain, work: work.to_i }
      blk = Bitcoin::Storage::Models::Block.new(self, data)

      blk.ver = block.ver
      blk.prev_block = block.prev_block
      blk.mrkl_root = block.mrkl_root
      blk.time = block.time
      blk.bits = block.bits
      blk.nonce = block.nonce

      blk.aux_pow = block.aux_pow  if block.aux_pow

      blk.hashes = block.hashes
      blk.flags = block.flags

      blk.recalc_block_hash
      blk
    end

    # wrap given +transaction+ into Models::Transaction
    def wrap_tx(transaction, block_id = nil)
      return nil  unless transaction

      data = {id: transaction.hash, blk_id: 0, size: transaction.to_payload.bytesize, idx: 0}
      tx = Bitcoin::Storage::Models::Tx.new(self, data)

      transaction.in.map.with_index {|i, idx| tx.add_in wrap_txin(i, tx, idx) }
      transaction.out.map.with_index {|o, idx| tx.add_out wrap_txout(o, tx, idx) }

      tx.hash = tx.hash_from_payload(tx.to_payload)
      tx
    end

    # wrap given +input+ into Models::TxIn
    def wrap_txin(input, tx, idx)
      return nil  unless input
      data = { tx_id: tx.hash, tx_idx: idx }
      txin = Bitcoin::Storage::Models::TxIn.new(self, data)
      txin.prev_out = input.prev_out
      txin.prev_out_index = input.prev_out_index
      txin.script_sig_length = input.script_sig.bytesize
      txin.script_sig = input.script_sig
      txin.sequence = input.sequence
      txin
    end

    # wrap given +output+ into Models::TxOut
    def wrap_txout(output, tx, idx, script = nil)
      return nil  unless output
      script ||= Bitcoin::Script.new(output.pk_script)
      data = {
        hash160: Bitcoin.hash160_from_address(script.get_address),
        type: script.type}
      txout = Bitcoin::Storage::Models::TxOut.new(self, data)
      txout.value = output.value
      txout.pk_script = output.pk_script
      txout
    end

    def storage_mode
      :spv
    end

  end

end
