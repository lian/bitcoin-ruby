require 'sequel'
require 'bitcoin/storage/sequel_store/sequel_migrations'

module Bitcoin::Storage::Backends

  class SequelStore < StoreBase

    attr_accessor :db

    include Bitcoin::Storage::Backends::SequelMigrations

    def initialize config
      @config = config
      connect
      super config
    end
    
    def connect
      @db = Sequel.connect(@config[:db])
      migrate
    end

    def reset
      [:blk, :blk_tx, :tx, :txin, :txout].each {|table| @db[table].delete}
    end

    def store_block(blk)
      @db.transaction do
        block = @db[:blk][:hash => htb(blk.hash).to_sequel_blob]
        return block[:depth]  if block

        prev_block = get_block(hth(blk.prev_block.reverse))
        if !prev_block && blk.hash != Bitcoin::network[:genesis_hash]
          log.warn { "Invalid Block: #{blk.hash} - prev_block not found" }
          return nil
        end
        if prev_block
          depth = prev_block.depth + 1
        else
          depth = 0
        end
        block_id = @db[:blk].insert({
            :hash => htb(blk.hash).to_sequel_blob,
            :depth => depth,
            :version => blk.ver,
            :prev_hash => blk.prev_block.reverse.to_sequel_blob,
            :mrkl_root => blk.mrkl_root.reverse.to_sequel_blob,
            :time => blk.time,
            :bits => blk.bits,
            :nonce => blk.nonce,
            :blk_size => blk.payload.bytesize,
          })
        blk.tx.each_with_index do |tx, idx|
          tx_id = store_tx(tx)
          @db[:blk_tx].insert({
              :blk_id => block_id,
              :tx_id => tx_id,
              :idx => idx,
            })
        end

        log.info { "new head #{blk.hash} - #{get_depth}" }
        depth
      end
    end

    def store_tx(tx)
      @db.transaction do
        transaction = @db[:tx][:hash => htb(tx.hash).to_sequel_blob]
        return transaction[:id]  if transaction

        tx_id = @db[:tx].insert({
            :hash => htb(tx.hash).to_sequel_blob,
            :version => tx.ver,
            :lock_time => tx.lock_time,
            :coinbase => tx.in.size==1 && tx.in[0].coinbase?,
            :tx_size => tx.payload.bytesize,
          })
        tx.in.each_with_index {|i, idx| store_txin(tx_id, i, idx)}
        tx.out.each_with_index {|o, idx| store_txout(tx_id, o, idx)}
        tx_id
      end
    end

    def store_txin(tx_id, txin, idx)
      @db[:txin].insert({
          :tx_id => tx_id,
          :tx_idx => idx,
          :script_sig => txin.script_sig.to_sequel_blob,
          :prev_out => txin.prev_out.to_sequel_blob,
          :prev_out_index => txin.prev_out_index,
          :sequence => txin.sequence.unpack("I")[0],
        })
    end

    def store_txout(tx_id, txout, idx)
      @db[:txout].insert({
          :tx_id => tx_id,
          :tx_idx => idx,
          :pk_script => txout.pk_script.to_sequel_blob,
          :value => txout.value,
          :hash160 => Bitcoin::Script.new(txout.pk_script).get_hash160
        })
    end


    def has_block(blk_hash)
      !!@db[:blk].where(:hash => htb(blk_hash).to_sequel_blob).get(1)
    end

    def has_tx(tx_hash)
      !!@db[:tx].where(:hash => htb(tx_hash).to_sequel_blob).get(1)
    end

    def get_head
      wrap_block(@db[:blk].order(:depth).last)
    end

    def get_depth
      return -1  if @db[:blk].count == 0
      @db[:blk][:hash => htb(get_head.hash).to_sequel_blob][:depth]
    end

    def get_block(blk_hash)
      wrap_block(@db[:blk][:hash => htb(blk_hash).to_sequel_blob])
    end

    def get_block_by_depth(depth)
      wrap_block(@db[:blk][:depth => depth])
    end

    def get_block_by_prev_hash(prev_hash)
      wrap_block(@db[:blk][:prev_hash => htb(prev_hash).to_sequel_blob])
    end

    def get_block_by_tx(tx_hash)
      tx = @db[:tx][:hash => htb(tx_hash).to_sequel_blob]
      return nil  unless tx
      parent = @db[:blk_tx][:tx_id => tx[:id]]
      return nil  unless parent
      wrap_block(@db[:blk][:id => parent[:blk_id]])
    end

    def get_block_by_id(block_id)
      wrap_block(@db[:blk][:id => block_id])
    end

    def get_tx(tx_hash)
      wrap_tx(@db[:tx][:hash => htb(tx_hash).to_sequel_blob])
    end

    def get_tx_by_id(tx_id)
      wrap_tx(@db[:tx][:id => tx_id])
    end

    def get_txin_for_txout(tx_hash, txout_idx)
      tx_hash = htb(tx_hash).reverse.to_sequel_blob
      wrap_txin(@db[:txin][:prev_out => tx_hash, :prev_out_index => txout_idx])
    end

    def get_txouts_for_pk_script(script)
      txouts = @db[:txout].filter(:pk_script => script.to_sequel_blob).order(:id)
      txouts.map{|txout| wrap_txout(txout)}
    end

    def get_txouts_for_hash160(hash160)
      @db[:txout].where(:hash160 => hash160).map{|o| wrap_txout(o) }
    end

    def get_unconfirmed_tx
      @db[:unconfirmed].map{|t| wrap_tx(t)}
    end

    def wrap_block(block)
      return nil  unless block

      data = {:id => block[:id], :depth => block[:depth]}
      blk = Bitcoin::Storage::Models::Block.new(self, data)

      blk.ver = block[:version]
      blk.prev_block = block[:prev_hash].reverse
      blk.mrkl_root = block[:mrkl_root].reverse
      blk.time = block[:time].to_i
      blk.bits = block[:bits]
      blk.nonce = block[:nonce]
      parents = db[:blk_tx].filter(:blk_id => block[:id])
        .order(:idx) rescue []
      parents.each do |parent|
        transaction = db[:tx][:id => parent[:tx_id]]
        blk.tx << wrap_tx(transaction)
      end

      blk.recalc_block_hash
      blk
    end

    def wrap_tx(transaction)
      return nil  unless transaction

      parent = @db[:blk_tx][:tx_id => transaction[:id]]
      block_id = parent ? parent[:blk_id] : nil
      data = {:id => transaction[:id], :blk_id => block_id}
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

    def wrap_txin(input)
      return nil  unless input
      data = {:id => input[:id], :tx_id => input[:tx_id], :tx_idx => input[:tx_idx]}
      txin = Bitcoin::Storage::Models::TxIn.new(self, data)
      txin.prev_out = input[:prev_out]
      txin.prev_out_index = input[:prev_out_index]
      txin.script_sig_length = input[:script_sig].bytesize
      txin.script_sig = input[:script_sig]
      txin.sequence = [input[:sequence]].pack("I")
      txin
    end

    def wrap_txout(output)
      return nil  unless output
      data = {:id => output[:id], :tx_id => output[:tx_id], :tx_idx => output[:tx_idx],
        :hash160 => output[:hash160]}
      txout = Bitcoin::Storage::Models::TxOut.new(self, data)
      txout.value = output[:value]
      txout.pk_script_length = output[:pk_script].bytesize
      txout.pk_script = output[:pk_script]
      txout
    end


    def hth(bin); bin.unpack("H*")[0]; end
    def htb(hex); [hex].pack("H*"); end

  end

end
