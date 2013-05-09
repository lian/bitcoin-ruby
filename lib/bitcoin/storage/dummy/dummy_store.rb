# encoding: ascii-8bit

module Bitcoin::Storage::Backends
  class DummyStore < StoreBase

    attr_accessor :blk, :tx

    def initialize *args
      reset
      super(*args)
    end

    def reset
      @blk, @tx = [], {}
    end

    def persist_block(blk, chain, depth, prev_work = 0)
      return [depth, chain]  unless blk && chain == 0
      if block = get_block(blk.hash)
        log.info { "Block already stored; skipping" }
        return false
      end

      blk.tx.each {|tx| store_tx(tx) }
      @blk << blk

      log.info { "NEW HEAD: #{blk.hash} DEPTH: #{get_depth}" }
      [depth, chain]
    end

    def store_tx(tx, validate = true)
      if @tx.keys.include?(tx.hash)
        log.info { "Tx already stored; skipping" }
        return tx
      end
      @tx[tx.hash] = tx
    end

    def has_block(blk_hash)
      !!get_block(blk_hash)
    end

    def has_tx(tx_hash)
      !!get_tx(tx_hash)
    end

    def get_depth
      @blk.size - 1
    end

    def get_head
      wrap_block(@blk[-1])
    end

    def get_block_by_depth(depth)
      wrap_block(@blk[depth])
    end

    def get_block_by_prev_hash(hash)
      wrap_block(@blk.find {|blk| blk.prev_block == [hash].pack("H*").reverse})
    end

    def get_block(blk_hash)
      wrap_block(@blk.find {|blk| blk.hash == blk_hash})
    end

    def get_block_by_id(blk_id)
      wrap_block(@blk[blk_id])
    end

    def get_block_by_tx(tx_hash)
      wrap_block(@blk.find {|blk| blk.tx.map(&:hash).include?(tx_hash) })
    end

    def get_tx(tx_hash)
      transaction = @tx[tx_hash]
      return nil  unless transaction
      wrap_tx(transaction)
    end

    def get_tx_by_id(tx_id)
      wrap_tx(@tx[tx_id])
    end

    def get_txin_for_txout(tx_hash, txout_idx)
      txin = @tx.values.map(&:in).flatten.find {|i| i.prev_out_index == txout_idx &&
        i.prev_out == [tx_hash].pack("H*").reverse }
      wrap_txin(txin)
    end

    def get_txouts_for_pk_script(script)
      txouts = @tx.values.map(&:out).flatten.select {|o| o.pk_script == script}
      txouts.map {|o| wrap_txout(o) }
    end

    def get_txouts_for_hash160(hash160, unconfirmed = false)
      @tx.values.map(&:out).flatten.map {|o|
        o = wrap_txout(o)
        o.hash160 == hash160 ? o : nil
      }.compact
    end

    def wrap_block(block)
      return nil  unless block
      data = {:id => @blk.index(block), :depth => @blk.index(block), :work => @blk.index(block), :chain => 0}
      blk = Bitcoin::Storage::Models::Block.new(self, data)
      [:ver, :prev_block, :mrkl_root, :time, :bits, :nonce].each do |attr|
        blk.send("#{attr}=", block.send(attr))
      end
      block.tx.each do |tx|
        blk.tx << get_tx(tx.hash)
      end
      blk.recalc_block_hash
      blk
    end

    def wrap_tx(transaction)
      return nil  unless transaction
      blk = @blk.find{|b| b.tx.include?(transaction)}
      data = {:id => transaction.hash, :blk_id => @blk.index(blk)}
      tx = Bitcoin::Storage::Models::Tx.new(self, data)
      tx.ver = transaction.ver
      tx.lock_time = transaction.lock_time
      transaction.in.each {|i| tx.add_in(wrap_txin(i))}
      transaction.out.each {|o| tx.add_out(wrap_txout(o))}
      tx.hash = tx.hash_from_payload(tx.to_payload)
      tx
    end

    def wrap_txin(input)
      return nil  unless input
      tx = @tx.values.find{|t| t.in.include?(input)}
      data = {:tx_id => tx.hash, :tx_idx => tx.in.index(input)}
      txin = Bitcoin::Storage::Models::TxIn.new(self, data)
      [:prev_out, :prev_out_index, :script_sig_length, :script_sig, :sequence].each do |attr|
        txin.send("#{attr}=", input.send(attr))
      end
      txin
    end

    def wrap_txout(output)
      return nil  unless output
      tx = @tx.values.find{|t| t.out.include?(output)}
      data = {:tx_id => tx.hash, :tx_idx => tx.out.index(output),
        :hash160 => Bitcoin::Script.new(output.pk_script).get_hash160 }
      txout = Bitcoin::Storage::Models::TxOut.new(self, data)
      [:value, :pk_script_length, :pk_script].each do |attr|
        txout.send("#{attr}=", output.send(attr))
      end
      txout
    end

    def to_s
      "DummyStore"
    end

  end
end
