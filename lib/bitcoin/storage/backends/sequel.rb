require 'sequel'

module Bitcoin::Storage::Backends

  class SequelStore < Base

    attr_accessor :db

    def initialize config
      @config = config
      connect
      super config
    end
    
    def connect
      @db = Sequel.connect(@config[:db])
    end

    def reset
      [:blocks, :transactions_parents, :transactions,
       :inputs, :outputs].each {|table| @db[table].delete}
    end

    def get_head
      hex(@db[:blocks].order(:depth).last[:block_hash])
    end

    def get_depth
      return -1  if @db[:blocks].count == 0
      @db[:blocks][:block_hash => bin(get_head).to_sequel_blob][:depth]
    end

    def store_block(blk)
      if get_block(blk.hash)
        log.debug { "Block #{blk.hash} already stored" }
        return true
      end

      prev_block = get_block(hex(blk.prev_block.reverse))
      if !prev_block && blk.hash != Bitcoin::network[:genesis_hash]
        log.warn { "Invalid Block: #{blk.hash} - prev_block not found" }
        return nil
      end

      depth = (get_block_depth(prev_block.hash) + 1 rescue 0)
      block_id = @db[:blocks].insert({
        :block_hash => bin(blk.hash).to_sequel_blob,
        :depth => depth,
        :version => blk.ver,
        :prev_block_hash => blk.prev_block.reverse.to_sequel_blob,
        :merkle => blk.mrkl_root.to_sequel_blob,
        :when_created => Time.at(blk.time),
        :when_found => Time.now,
        :bits_head => blk.bits >> 24,
        :bits_body => blk.bits & 0x00ffffff,
        :nonce => blk.nonce,
        :block_size => blk.payload.bytesize,
        :space => 0,
        :span_left => 0,
        :span_right => 0,
      })

      blk.tx.each_with_index do |tx, idx|
        tx_id = store_tx(tx)
        @db[:transactions_parents].insert({
          :block_id => block_id,
          :transaction_id => tx_id,
          :index_in_block => idx,
        })
      end

      log.info { "new head #{blk.hash} - #{get_depth}" }
      depth
    end

    def get_block(blk_hash)
      block = @db[:blocks][:block_hash => bin(blk_hash).to_sequel_blob]
      return nil  unless block
      blk = Bitcoin::Protocol::Block.new(nil)
      db = @db; store = self
      blk.instance_eval do
        @ver = block[:version]
        @prev_block = block[:prev_block_hash].reverse
        @mrkl_root = block[:merkle]
        @time = block[:when_created].to_i
        @bits = ((block[:bits_head] << 24) | block[:bits_body])
        @nonce = block[:nonce]
        parents = db[:transactions_parents].filter(:block_id => block[:block_id])
          .order(:index_in_block) rescue []
        parents.each do |parent|
          transaction = db[:transactions][:transaction_id => parent[:transaction_id]]
          @tx << store.get_tx(transaction[:transaction_hash].unpack("H*")[0])
        end
        recalc_block_hash
      end
      blk
    end

    def get_block_by_depth(depth)
      get_block(@db[:blocks][:depth => depth][:block_hash].unpack("H*")[0]) rescue nil
    end

    def get_block_depth(blk_hash)
      @db[:blocks][:block_hash => bin(blk_hash).to_sequel_blob][:depth]
    end

    def store_tx(tx)
      if transaction = @db[:transactions][:transaction_hash => bin(tx.hash).to_sequel_blob]
        return transaction[:transaction_id]
      end
      tx_id = @db[:transactions].insert({
        :transaction_hash => bin(tx.hash).to_sequel_blob,
        :version => tx.ver,
        :locktime => tx.lock_time,
        :coinbase => tx.in.size==1 && tx.in[0].coinbase?,
        :transaction_size => tx.payload.bytesize,
      })
      tx.in.each_with_index {|i, idx| store_txin(tx_id, i, idx)}
      tx.out.each_with_index {|o, idx| store_txout(tx_id, o, idx)}
      tx_id
    end

    def store_txin(tx_id, txin, idx)
      @db[:inputs].insert({
        :transaction_id => tx_id,
        :index_in_parent => idx,
        :script => txin.script_sig.to_sequel_blob,
        :previous_output_hash => txin.prev_out.to_sequel_blob,
        :previous_output_index => txin.prev_out_index,
        :sequence => txin.sequence.unpack("I")[0],
      })
    end

    def store_txout(tx_id, txout, idx)
      @db[:outputs].insert({
        :transaction_id => tx_id,
        :index_in_parent => idx,
        :script => txout.pk_script.to_sequel_blob,
        :value => txout.value / 1e8,
      })
    end

    def get_tx(tx_hash)
      transaction = @db[:transactions][:transaction_hash => bin(tx_hash).to_sequel_blob]
      return nil  unless transaction
      tx = Bitcoin::Protocol::Tx.new(nil)
      db = @db
      tx.instance_eval do
        inputs = db[:inputs].filter(:transaction_id => transaction[:transaction_id])
          .order(:index_in_parent)
        inputs.each do |input|
          txin = Bitcoin::Protocol::TxIn.new
          txin.prev_out = input[:previous_output_hash]
          txin.prev_out_index = input[:previous_output_index]
          txin.script_sig_length = input[:script].bytesize
          txin.script_sig = input[:script]
          txin.sequence = [input[:sequence]].pack("I")
          add_in(txin)
        end

        outputs = db[:outputs].filter(:transaction_id => transaction[:transaction_id])
          .order(:index_in_parent)
        outputs.each do |output|
          txout = Bitcoin::Protocol::TxOut.new
          txout.value = (output[:value].to_f * 1e8).to_i
          txout.pk_script_length = output[:script].bytesize
          txout.pk_script = output[:script]
          add_out(txout)
        end
        @ver = transaction[:version]
        @lock_time = transaction[:locktime]
        @hash = hash_from_payload(@payload = to_payload)
      end
      tx
    end

    def hex(bin); bin.unpack("H*")[0]; end
    def bin(hex); [hex].pack("H*"); end

  end

end
