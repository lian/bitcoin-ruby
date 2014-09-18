# encoding: ascii-8bit

Bitcoin.require_dependency :sequel, message:
  "Note: You will also need an adapter for your database like sqlite3, mysql2, postgresql"

module Bitcoin::Storage::Backends

  # Storage backend using Sequel to connect to arbitrary SQL databases.
  # Inherits from StoreBase and implements its interface.
  class SequelStore < SequelStoreBase

    # sequel database connection
    attr_accessor :db

    DEFAULT_CONFIG = {
      # TODO
      mode: :full,

      # cache head block. only the instance that is updating the head should do this.
      cache_head: false,

      # store an index of tx.nhash values
      index_nhash: false
    }

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
          existing_tx = Hash[*@db[:tx].filter(hash: blk.tx.map {|tx| tx.hash.htb.blob }).map { |tx| [tx[:hash].hth, tx[:id]] }.flatten]
          blk.tx.each.with_index do |tx, idx|
            existing = existing_tx[tx.hash]
            existing ? blk_tx[idx] = existing : new_tx << [tx, idx]
          end

          new_tx_ids = fast_insert(:tx, new_tx.map {|tx, _| tx_data(tx) }, return_ids: true)
          new_tx_ids.each.with_index {|tx_id, idx| blk_tx[new_tx[idx][1]] = tx_id }

          fast_insert(:blk_tx, blk_tx.map.with_index {|id, idx| { blk_id: block_id, tx_id: id, idx: idx } })

          # store txins
          fast_insert(:txin, new_tx.map.with_index {|tx, tx_idx|
            tx, _ = *tx
            tx.in.map.with_index {|txin, txin_idx|
              p2sh_type = nil
              if @config[:index_p2sh_type] && !txin.coinbase? && (script = tx.scripts[txin_idx]) && script.is_p2sh?
                p2sh_type = Bitcoin::Script.new(script.inner_p2sh_script).type
              end
              txin_data(new_tx_ids[tx_idx], txin, txin_idx, p2sh_type) } }.flatten)

          # store txouts
          txout_i = 0
          txout_ids = fast_insert(:txout, new_tx.map.with_index {|tx, tx_idx|
            tx, _ = *tx
            tx.out.map.with_index {|txout, txout_idx|
              script_type, a, n = *parse_script(txout, txout_i, tx.hash, txout_idx)
              addrs += a; names += n; txout_i += 1
              txout_data(new_tx_ids[tx_idx], txout, txout_idx, script_type) } }.flatten, return_ids: true)

          # store addrs
          persist_addrs addrs.map {|i, addr| [txout_ids[i], addr]}
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

    # bulk-store addresses and txout mappings
    def persist_addrs addrs
      addr_txouts, new_addrs = [], []

      # find addresses that are already there
      existing_addr = {}
      addrs.each do |i, addr|
        hash160 = Bitcoin.hash160_from_address(addr)
        type = Bitcoin.address_type(addr)
        if existing = @db[:addr][hash160: hash160, type: ADDRESS_TYPES.index(type)]
          existing_addr[[hash160, type]] = existing[:id]
        end
      end

      # iterate over all txouts, grouped by hash160
      addrs.group_by {|_, a| a }.each do |addr, txouts|
        hash160 = Bitcoin.hash160_from_address(addr)
        type = Bitcoin.address_type(addr)

        if existing_id = existing_addr[[hash160, type]]
          # link each txout to existing address
          txouts.each {|id, _| addr_txouts << [existing_id, id] }
        else
          # collect new address/txout mapping
          new_addrs << [[hash160, type], txouts.map {|id, _| id }]
        end
      end

      # insert all new addresses
      new_addr_ids = fast_insert(:addr, new_addrs.map {|hash160_and_type, txout_id|
          hash160, type = *hash160_and_type
          { hash160: hash160, type: ADDRESS_TYPES.index(type) }
        }, return_ids: true)


      # link each new txout to the new addresses
      new_addr_ids.each.with_index do |addr_id, idx|
        new_addrs[idx][1].each do |txout_id|
          addr_txouts << [addr_id, txout_id]
        end
      end

      # insert addr/txout links
      fast_insert(:addr_txout, addr_txouts.map {|addr_id, txout_id| { addr_id: addr_id, txout_id: txout_id }})
    end

    # prepare transaction data for storage
    def tx_data tx
      data = {
        hash: tx.hash.htb.blob,
        version: tx.ver, lock_time: tx.lock_time,
        coinbase: tx.in.size == 1 && tx.in[0].coinbase?,
        tx_size: tx.payload.bytesize }
      data[:nhash] = tx.nhash.htb.blob  if @config[:index_nhash]
      data
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
    def txin_data tx_id, txin, idx, p2sh_type = nil
      data = {
        tx_id: tx_id, tx_idx: idx,
        script_sig: txin.script_sig.blob,
        prev_out: txin.prev_out.blob,
        prev_out_index: txin.prev_out_index,
        sequence: txin.sequence.unpack("V")[0],
      }
      data[:p2sh_type] = SCRIPT_TYPES.index(p2sh_type)  if @config[:index_p2sh_type]
      data
    end

    # store input +txin+
    def store_txin(tx_id, txin, idx, p2sh_type = nil)
      @db[:txin].insert(txin_data(tx_id, txin, idx, p2sh_type))
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

    # check if block +blk_hash+ exists in the main chain
    def has_block(blk_hash)
      !!@db[:blk].where(:hash => blk_hash.htb.blob, :chain => 0).get(1)
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

    # get block id in the main chain by given +tx_id+
    def get_block_id_for_tx_id(tx_id)
      @db[:blk_tx].join(:blk, id: :blk_id)
        .where(tx_id: tx_id, chain: MAIN).first[:blk_id] rescue nil
    end

    # get transaction for given +tx_hash+
    def get_tx(tx_hash)
      wrap_tx(@db[:tx][:hash => tx_hash.htb.blob])
    end

    # get array of txes with given +tx_hashes+
    def get_txs(tx_hashes)
      txs = db[:tx].filter(hash: tx_hashes.map{|h| h.htb.blob})
      txs_ids = txs.map {|tx| tx[:id]}
      return [] if txs_ids.empty?

      # we fetch all needed block ids, inputs and outputs to avoid doing number of queries propertional to number of transactions
      block_ids = Hash[*db[:blk_tx].join(:blk, id: :blk_id).filter(tx_id: txs_ids, chain: 0).map {|b| [b[:tx_id], b[:blk_id]] }.flatten]
      inputs = db[:txin].filter(:tx_id => txs_ids).order(:tx_idx).map.group_by{ |txin| txin[:tx_id] }
      outputs = db[:txout].filter(:tx_id => txs_ids).order(:tx_idx).map.group_by{ |txout| txout[:tx_id] }

      txs.map {|tx| wrap_tx(tx, block_ids[tx[:id]], inputs: inputs[tx[:id]], outputs: outputs[tx[:id]]) }
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

    # optimized version of Storage#get_txins_for_txouts
    def get_txins_for_txouts(txouts)
      @db[:txin].filter([:prev_out, :prev_out_index] => txouts.map{|tx_hash, tx_idx| [tx_hash.htb_reverse.blob, tx_idx]}).map{|i| wrap_txin(i)}
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
    def get_txouts_for_hash160(hash160, type = :hash160, unconfirmed = false)
      addr = @db[:addr][hash160: hash160, type: ADDRESS_TYPES.index(type)]
      return []  unless addr
      txouts = @db[:addr_txout].where(addr_id: addr[:id])
        .map{|t| @db[:txout][id: t[:txout_id]] }
        .map{|o| wrap_txout(o) }
      unless unconfirmed
        txouts.select!{|o| @db[:blk][id: o.get_tx.blk_id][:chain] == MAIN rescue false }
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

      blk_tx = db[:blk_tx].filter(blk_id: block[:id]).join(:tx, id: :tx_id).order(:idx)

      # fetch inputs and outputs for all transactions in the block to avoid additional queries for each transaction
      inputs = db[:txin].filter(:tx_id => blk_tx.map{ |tx| tx[:id] }).order(:tx_idx).map.group_by{ |txin| txin[:tx_id] }
      outputs = db[:txout].filter(:tx_id => blk_tx.map{ |tx| tx[:id] }).order(:tx_idx).map.group_by{ |txout| txout[:tx_id] }

      blk.tx = blk_tx.map { |tx| wrap_tx(tx, block[:id], inputs: inputs[tx[:id]], outputs: outputs[tx[:id]]) }

      blk.hash = block[:hash].hth
      blk
    end

    # wrap given +transaction+ into Models::Transaction
    def wrap_tx(transaction, block_id = nil, prefetched = {})
      return nil  unless transaction

      block_id ||= @db[:blk_tx].join(:blk, id: :blk_id)
        .where(tx_id: transaction[:id], chain: 0).first[:blk_id] rescue nil

      data = {id: transaction[:id], blk_id: block_id, size: transaction[:tx_size], idx: transaction[:idx]}
      tx = Bitcoin::Storage::Models::Tx.new(self, data)

      inputs = prefetched[:inputs] || db[:txin].filter(:tx_id => transaction[:id]).order(:tx_idx)
      inputs.each { |i| tx.add_in(wrap_txin(i)) }

      outputs = prefetched[:outputs] || db[:txout].filter(:tx_id => transaction[:id]).order(:tx_idx)
      outputs.each { |o| tx.add_out(wrap_txout(o)) }
      tx.ver = transaction[:version]
      tx.lock_time = transaction[:lock_time]
      tx.hash = transaction[:hash].hth
      tx
    end

    # wrap given +input+ into Models::TxIn
    def wrap_txin(input)
      return nil  unless input
      data = { :id => input[:id], :tx_id => input[:tx_id], :tx_idx => input[:tx_idx],
        :p2sh_type => input[:p2sh_type] ? SCRIPT_TYPES[input[:p2sh_type]] : nil }
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

    protected

    # Abstraction for doing many quick inserts.
    #
    # * +table+ - db table name
    # * +data+ - a table of hashes with the same keys
    # * +opts+
    # ** return_ids - if true table of inserted rows ids will be returned
    def fast_insert(table, data, opts={})
      return [] if data.empty?
      # For postgres we are using COPY which is much faster than separate INSERTs
      if @db.adapter_scheme == :postgres

        columns = data.first.keys
        if opts[:return_ids]
          ids = db.transaction do
            # COPY does not return ids, so we set ids manually based on current sequence value
            # We lock the table to avoid inserts that could happen in the middle of COPY
            db.execute("LOCK TABLE #{table} IN SHARE UPDATE EXCLUSIVE MODE")
            first_id = db.fetch("SELECT nextval('#{table}_id_seq') AS id").first[:id]

            # Blobs need to be represented in the hex form (yes, we do hth on them earlier, could be improved
            # \\x is the format of bytea as hex encoding in postgres
            csv = data.map.with_index{|x,i| [first_id + i, columns.map{|c| x[c].kind_of?(Sequel::SQL::Blob) ? "\\x#{x[c].hth}" : x[c]}].join(',')}.join("\n")
            db.copy_into(table, columns: [:id] + columns, format: :csv, data: csv)
            last_id = first_id + data.size - 1

            # Set sequence value to max id, last arg true means it will be incremented before next value
            db.execute("SELECT setval('#{table}_id_seq', #{last_id}, true)")
            (first_id..last_id).to_a # returned ids
          end
        else
          csv = data.map{|x| columns.map{|c| x[c].kind_of?(Sequel::SQL::Blob) ? "\\x#{x[c].hth}" : x[c]}.join(',')}.join("\n")
          @db.copy_into(table, format: :csv, columns: columns, data: csv)
        end

      else

        # Life is simple when your are not optimizing ;)
        @db[table].insert_multiple(data)

      end
    end

  end

end
