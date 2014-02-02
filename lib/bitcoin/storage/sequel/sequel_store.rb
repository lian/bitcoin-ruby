# encoding: ascii-8bit

Bitcoin.require_dependency :sequel, message:
  "Note: You will also need an adapter for your database like sqlite3, mysql2, postgresql"

module Bitcoin::Storage::Backends

  # Storage backend using Sequel to connect to arbitrary SQL databases.
  # Inherits from StoreBase and implements its interface.
  class SequelStore < StoreBase

    # sequel database connection
    attr_accessor :db

    DEFAULT_CONFIG = { mode: :full, cache_head: false }

    # create sequel store with given +config+
    def initialize config, *args
      super config, *args
    end

    # connect to database
    def connect
      super
    end

    # reset database; delete all data
    def reset
      [:blk, :blk_tx, :tx, :txin, :txout, :addr, :addr_txout, :names].each {|table| @db[table].delete }
      @head = nil
    end

    # persist given block +blk+ to storage.
    def persist_block blk, chain, depth, prev_work = 0
      @db.transaction do
        attrs = {
          :hash => blk.hash.htb.blob,
          :depth => depth,
          :chain => chain,
          :version => blk.ver,
          :prev_hash => blk.prev_block.reverse.blob,
          :mrkl_root => blk.mrkl_root.reverse.blob,
          :time => blk.time,
          :bits => blk.bits,
          :nonce => blk.nonce,
          :blk_size => blk.to_payload.bytesize,
          :work => (prev_work + blk.block_work).to_s
        }
        attrs[:aux_pow] = blk.aux_pow.to_payload.blob  if blk.aux_pow
        existing = @db[:blk].filter(:hash => blk.hash.htb.blob)
        if existing.any?
          existing.update attrs
          block_id = existing.first[:id]
        else
          block_id = @db[:blk].insert(attrs)
          blk_tx, new_tx, addrs, names = [], [], [], []

          # store tx
          blk.tx.each.with_index do |tx, idx|
            existing = @db[:tx][hash: tx.hash.htb.blob]
            existing ? blk_tx[idx] = existing[:id] : new_tx << [tx, idx]
          end
          new_tx_ids = @db[:tx].insert_multiple(new_tx.map {|tx, _| tx_data(tx) })
          new_tx_ids.each.with_index {|tx_id, idx| blk_tx[new_tx[idx][1]] = tx_id }

          @db[:blk_tx].insert_multiple(blk_tx.map.with_index {|id, idx|
            { blk_id: block_id, tx_id: id, idx: idx } })

          # store txins
          txin_ids = @db[:txin].insert_multiple(new_tx.map.with_index {|tx, tx_idx|
            tx, _ = *tx
            tx.in.map.with_index {|txin, txin_idx|
              txin_data(new_tx_ids[tx_idx], txin, txin_idx) } }.flatten)

          # store txouts
          txout_i = 0
          txout_ids = @db[:txout].insert_multiple(new_tx.map.with_index {|tx, tx_idx|
            tx, _ = *tx
            tx.out.map.with_index {|txout, txout_idx|
              script_type, a, n = *parse_script(txout, txout_i, tx.hash, txout_idx)
              addrs += a; names += n; txout_i += 1
              txout_data(new_tx_ids[tx_idx], txout, txout_idx, script_type) } }.flatten)

          # store addrs
          persist_addrs addrs.map {|i, h| [txout_ids[i], h]}
          names.each {|i, script| store_name(script, txout_ids[i]) }
        end
        @head = wrap_block(attrs.merge(id: block_id))  if chain == MAIN
        @db[:blk].where(:prev_hash => blk.hash.htb.blob, :chain => ORPHAN).each do |b|
          log.debug { "connecting orphan #{b[:hash].hth}" }
          begin
            store_block(get_block(b[:hash].hth))
          rescue SystemStackError
            EM.defer { store_block(get_block(b[:hash].hth)) }  if EM.reactor_running?
          end
        end
        return depth, chain
      end
    end

    def reorg new_side, new_main
      @db.transaction do
        @db[:blk].where(hash: new_side.map {|h| h.htb.blob }).update(chain: SIDE)
        new_main.each do |block_hash|
          unless @config[:skip_validation]
            get_block(block_hash).validator(self).validate(raise_errors: true)
          end
          @db[:blk].where(hash: block_hash.htb.blob).update(chain: MAIN)
        end
      end
    end

    # parse script and collect address/txout mappings to index
    def parse_script txout, i, tx_hash = "", tx_idx
      addrs, names = [], []

      script = Bitcoin::Script.new(txout.pk_script) rescue nil
      if script
        if script.is_hash160? || script.is_pubkey?
          addrs << [i, script.get_hash160]
        elsif script.is_multisig?
          script.get_multisig_pubkeys.map do |pubkey|
            addrs << [i, Bitcoin.hash160(pubkey.unpack("H*")[0])]
          end
        elsif Bitcoin.namecoin? && script.is_namecoin?
          addrs << [i, script.get_hash160]
          names << [i, script]
        else
          log.info { "Unknown script type in #{tx_hash}:#{tx_idx}" }
          log.debug { script.to_string }
        end
        script_type = SCRIPT_TYPES.index(script.type)
      else
        log.error { "Error parsing script #{tx_hash}:#{tx_idx}" }
        script_type = SCRIPT_TYPES.index(:unknown)
      end
      [script_type, addrs, names]
    end

    # bulk-store addresses and txout mappings
    def persist_addrs addrs
      addr_txouts, new_addrs = [], []
      addrs.group_by {|_, a| a }.each do |hash160, txouts|
        if existing = @db[:addr][:hash160 => hash160]
          txouts.each {|id, _| addr_txouts << [existing[:id], id] }
        else
          new_addrs << [hash160, txouts.map {|id, _| id }]
        end
      end
      new_addr_ids = @db[:addr].insert_multiple(new_addrs.map {|hash160, txout_id|
        { hash160: hash160 } })
      new_addr_ids.each.with_index do |addr_id, idx|
        new_addrs[idx][1].each do |txout_id|
          addr_txouts << [addr_id, txout_id]
        end
      end
      @db[:addr_txout].insert_multiple(addr_txouts.map {|addr_id, txout_id|
        { addr_id: addr_id, txout_id: txout_id }})
    end

    # prepare transaction data for storage
    def tx_data tx
      { hash: tx.hash.htb.blob,
        version: tx.ver, lock_time: tx.lock_time,
        coinbase: tx.in.size == 1 && tx.in[0].coinbase?,
        tx_size: tx.payload.bytesize }
    end

    # store transaction +tx+
    def store_tx(tx, validate = true)
      @log.debug { "Storing tx #{tx.hash} (#{tx.to_payload.bytesize} bytes)" }
      tx.validator(self).validate(raise_errors: true)  if validate
      @db.transaction do
        transaction = @db[:tx][:hash => tx.hash.htb.blob]
        return transaction[:id]  if transaction
        tx_id = @db[:tx].insert(tx_data(tx))
        tx.in.each_with_index {|i, idx| store_txin(tx_id, i, idx)}
        tx.out.each_with_index {|o, idx| store_txout(tx_id, o, idx, tx.hash)}
        tx_id
      end
    end

    # prepare txin data for storage
    def txin_data tx_id, txin, idx
      { tx_id: tx_id, tx_idx: idx,
        script_sig: txin.script_sig.blob,
        prev_out: txin.prev_out.blob,
        prev_out_index: txin.prev_out_index,
        sequence: txin.sequence.unpack("V")[0] }
    end

    # store input +txin+
    def store_txin(tx_id, txin, idx)
      @db[:txin].insert(txin_data(tx_id, txin, idx))
    end

    # prepare txout data for storage
    def txout_data tx_id, txout, idx, script_type
      { tx_id: tx_id, tx_idx: idx,
        pk_script: txout.pk_script.blob,
        value: txout.value, type: script_type }
    end

    # store output +txout+
    def store_txout(tx_id, txout, idx, tx_hash = "")
      script_type, addrs, names = *parse_script(txout, idx, tx_hash, idx)
      txout_id = @db[:txout].insert(txout_data(tx_id, txout, idx, script_type))
      persist_addrs addrs.map {|i, h| [txout_id, h] }
      names.each {|i, script| store_name(script, txout_id) }
      txout_id
    end

    # delete transaction
    # TODO: also delete blk_tx mapping
    def delete_tx(hash)
      log.debug { "Deleting tx #{hash} since all its outputs are spent" }
      @db.transaction do
        tx = get_tx(hash)
        tx.in.each {|i| @db[:txin].where(:id => i.id).delete }
        tx.out.each {|o| @db[:txout].where(:id => o.id).delete }
        @db[:tx].where(:id => tx.id).delete
      end
    end

    # check if block +blk_hash+ exists
    def has_block(blk_hash)
      !!@db[:blk].where(:hash => blk_hash.htb.blob).get(1)
    end

    # check if transaction +tx_hash+ exists
    def has_tx(tx_hash)
      !!@db[:tx].where(:hash => tx_hash.htb.blob).get(1)
    end

    # get head block (highest block from the MAIN chain)
    def get_head
      (@config[:cache_head] && @head) ? @head :
        @head = wrap_block(@db[:blk].filter(:chain => MAIN).order(:depth).last)
    end

    def get_head_hash
      (@config[:cache_head] && @head) ? @head.hash :
        @head = @db[:blk].filter(:chain => MAIN).order(:depth).last[:hash].hth
    end

    # get depth of MAIN chain
    def get_depth
      depth = (@config[:cache_head] && @head) ? @head.depth :
        @depth = @db[:blk].filter(:chain => MAIN).order(:depth).last[:depth] rescue nil

      return -1  unless depth
      depth
    end

    # get block for given +blk_hash+
    def get_block(blk_hash)
      wrap_block(@db[:blk][:hash => blk_hash.htb.blob])
    end

    # get block by given +depth+
    def get_block_by_depth(depth)
      wrap_block(@db[:blk][:depth => depth, :chain => MAIN])
    end

    # get block by given +prev_hash+
    def get_block_by_prev_hash(prev_hash)
      wrap_block(@db[:blk][:prev_hash => prev_hash.htb.blob, :chain => MAIN])
    end

    # get block by given +tx_hash+
    def get_block_by_tx(tx_hash)
      tx = @db[:tx][:hash => tx_hash.htb.blob]
      return nil  unless tx
      parent = @db[:blk_tx][:tx_id => tx[:id]]
      return nil  unless parent
      wrap_block(@db[:blk][:id => parent[:blk_id]])
    end

    # get block by given +id+
    def get_block_by_id(block_id)
      wrap_block(@db[:blk][:id => block_id])
    end

    # get transaction for given +tx_hash+
    def get_tx(tx_hash)
      wrap_tx(@db[:tx][:hash => tx_hash.htb.blob])
    end

    # get transaction by given +tx_id+
    def get_tx_by_id(tx_id)
      wrap_tx(@db[:tx][:id => tx_id])
    end

    # get corresponding Models::TxIn for the txout in transaction
    # +tx_hash+ with index +txout_idx+
    def get_txin_for_txout(tx_hash, txout_idx)
      tx_hash = tx_hash.htb_reverse.blob
      wrap_txin(@db[:txin][:prev_out => tx_hash, :prev_out_index => txout_idx])
    end

    def get_txout_by_id(txout_id)
      wrap_txout(@db[:txout][:id => txout_id])
    end

    # get corresponding Models::TxOut for +txin+
    def get_txout_for_txin(txin)
      tx = @db[:tx][:hash => txin.prev_out.reverse.blob]
      return nil  unless tx
      wrap_txout(@db[:txout][:tx_idx => txin.prev_out_index, :tx_id => tx[:id]])
    end

    # get all Models::TxOut matching given +script+
    def get_txouts_for_pk_script(script)
      txouts = @db[:txout].filter(:pk_script => script.blob).order(:id)
      txouts.map{|txout| wrap_txout(txout)}
    end

    # get all Models::TxOut matching given +hash160+
    def get_txouts_for_hash160(hash160, unconfirmed = false)
      addr = @db[:addr][:hash160 => hash160]
      return []  unless addr
      txouts = @db[:addr_txout].where(:addr_id => addr[:id])
        .map{|t| @db[:txout][:id => t[:txout_id]] }
        .map{|o| wrap_txout(o) }
      unless unconfirmed
        txouts.select!{|o| @db[:blk][:id => o.get_tx.blk_id][:chain] == MAIN rescue false }
      end
      txouts
    end

    def get_txouts_for_name_hash(hash)
      @db[:names].filter(hash: hash).map {|n| get_txout_by_id(n[:txout_id]) }
    end

    # get all unconfirmed Models::TxOut
    def get_unconfirmed_tx
      @db[:unconfirmed].map{|t| wrap_tx(t)}
    end

    # Grab the position of a tx in a given block
    def get_idx_from_tx_hash(tx_hash)
      tx = @db[:tx][:hash => tx_hash.htb.blob]
      return nil  unless tx
      parent = @db[:blk_tx][:tx_id => tx[:id]]
      return nil  unless parent
      return parent[:idx]
    end

    # wrap given +block+ into Models::Block
    def wrap_block(block)
      return nil  unless block

      data = {:id => block[:id], :depth => block[:depth], :chain => block[:chain], :work => block[:work].to_i, :hash => block[:hash].hth, :size => block[:blk_size]}
      blk = Bitcoin::Storage::Models::Block.new(self, data)

      blk.ver = block[:version]
      blk.prev_block = block[:prev_hash].reverse
      blk.mrkl_root = block[:mrkl_root].reverse
      blk.time = block[:time].to_i
      blk.bits = block[:bits]
      blk.nonce = block[:nonce]

      blk.aux_pow = Bitcoin::P::AuxPow.new(block[:aux_pow])  if block[:aux_pow]

      db[:blk_tx].filter(blk_id: block[:id]).join(:tx, id: :tx_id)
        .order(:idx).each {|tx| blk.tx << wrap_tx(tx, block[:id]) }

      blk.recalc_block_hash
      blk
    end

    # wrap given +transaction+ into Models::Transaction
    def wrap_tx(transaction, block_id = nil)
      return nil  unless transaction

      block_id ||= @db[:blk_tx].join(:blk, id: :blk_id)
        .where(tx_id: transaction[:id], chain: 0).first[:blk_id] rescue nil

      data = {id: transaction[:id], blk_id: block_id, size: transaction[:tx_size], idx: transaction[:idx]}
      tx = Bitcoin::Storage::Models::Tx.new(self, data)

      inputs = db[:txin].filter(:tx_id => transaction[:id]).order(:tx_idx)
      inputs.each { |i| tx.add_in(wrap_txin(i)) }

      outputs = db[:txout].filter(:tx_id => transaction[:id]).order(:tx_idx)
      outputs.each { |o| tx.add_out(wrap_txout(o)) }
      tx.ver = transaction[:version]
      tx.lock_time = transaction[:lock_time]
      tx.hash = tx.hash_from_payload(tx.to_payload)
      tx
    end

    # wrap given +input+ into Models::TxIn
    def wrap_txin(input)
      return nil  unless input
      data = {:id => input[:id], :tx_id => input[:tx_id], :tx_idx => input[:tx_idx]}
      txin = Bitcoin::Storage::Models::TxIn.new(self, data)
      txin.prev_out = input[:prev_out]
      txin.prev_out_index = input[:prev_out_index]
      txin.script_sig_length = input[:script_sig].bytesize
      txin.script_sig = input[:script_sig]
      txin.sequence = [input[:sequence]].pack("V")
      txin
    end

    # wrap given +output+ into Models::TxOut
    def wrap_txout(output)
      return nil  unless output
      data = {:id => output[:id], :tx_id => output[:tx_id], :tx_idx => output[:tx_idx],
        :hash160 => output[:hash160], :type => SCRIPT_TYPES[output[:type]]}
      txout = Bitcoin::Storage::Models::TxOut.new(self, data)
      txout.value = output[:value]
      txout.pk_script = output[:pk_script]
      txout
    end

    # check data consistency of the top +count+ blocks. validates that
    # - the block hash computed from the stored data is the same
    # - the prev_hash is the same as the previous blocks' hash
    # - the merkle root computed from all transactions is correct
    def check_consistency count = 1000
      return  if get_depth < 1 || count <= 0
      depth = get_depth
      count = depth - 1  if count == -1
      count = depth - 1  if count >= depth
      log.info { "Checking consistency of last #{count} blocks..." }
      prev_blk = get_block_by_depth(depth - count - 1)
      (depth - count).upto(depth).each do |depth|
        blk = get_block_by_depth(depth)
        raise "Block hash #{blk.depth} invalid!"  unless blk.hash == blk.recalc_block_hash
        raise "Prev hash #{blk.depth} invalid!"  unless blk.prev_block.reverse.hth == prev_blk.hash
        raise "Merkle root #{blk.depth} invalid!"  unless blk.verify_mrkl_root
        print "#{blk.hash} #{blk.depth} OK\r"
        prev_blk = blk
      end
      log.info { "Last #{count} blocks are consistent." }
    end

    # get total received of +address+ address
    def get_received(address)
      return 0 unless Bitcoin.valid_address?(address)

      txouts = get_txouts_for_address(address)
      return 0 unless txouts.any?

      txouts.inject(0){ |m, out| m + out.value }

      # total = 0
      # txouts.each do |txout|
      #   tx = txout.get_tx
      #   total += txout.value
      # end
    end

  end

end
