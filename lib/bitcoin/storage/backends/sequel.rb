require 'pry'
require 'sequel'
require File.join(File.dirname(__FILE__), 'sequel_migrations.rb')

module Bitcoin::Storage::Backends

  module SequelModels

    module Block
      attr_reader :db, :depth
      def get_prev_block
        @store.get_block(hth(@prev_block))
      end
      def get_next_block
        block = @db[:blk][:prev_hash => htb(@hash).reverse.to_sequel_blob]
        return nil  unless block
        @store.get_block(hth(block[:hash].reverse))
      end
    end

    module Tx
      def get_block
        parent = @db[:blk_tx][:tx_id => @id]
        block = @db[:blk][:id => parent[:blk_id]]
        @store.get_block(hth(block[:hash].reverse))
      end
    end

    module TxIn
      def get_tx
        tx = @db[:tx][:id => @tx_id]
        @store.get_tx(tx[:hash].unpack("H*")[0])
      end
      def get_prev_out
        prev_tx = @db[:tx][:hash => @prev_out.reverse]
        @store.get_tx(prev_tx[:hash].unpack("H*")[0]).out[@prev_out_index]
      end
    end

    module TxOut
      def get_tx
        tx = @db[:tx][:id => @tx_id]
        @store.get_tx(tx[:hash].unpack("H*")[0])
      end
      def get_next_in
        tx = @db[:tx][:id => @tx_id]
        tx_hash = tx[:hash].reverse.to_sequel_blob
        next_in = @db[:txin][:prev_out => tx_hash]
        return nil  unless next_in
        @store.get_txin(next_in)
      end
    end
  end

  class SequelStore < Base

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

    def get_head
      hth(@db[:blk].order(:depth).last[:hash])
    end

    def get_depth
      return -1  if @db[:blk].count == 0
      @db[:blk][:hash => htb(get_head).to_sequel_blob][:depth]
    end

    def store_block(blk)
      block = @db[:blk][:hash => htb(blk.hash).to_sequel_blob]
      return block[:id]  if block

      prev_block = get_block(hth(blk.prev_block.reverse))
      if !prev_block && blk.hash != Bitcoin::network[:genesis_hash]
        log.warn { "Invalid Block: #{blk.hash} - prev_block not found" }
        return nil
      end
      if prev_block
        depth = get_block_depth(prev_block.hash) + 1 rescue binding.pry
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
#        :space => 0,
#        :span_left => 0,
#        :span_right => 0,
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

    def get_block(blk_hash)
      block = @db[:blk][:hash => htb(blk_hash).to_sequel_blob]
      return nil  unless block
      blk = Bitcoin::Protocol::Block.new(nil)
      db = @db; store = self
      blk.instance_eval do
        extend SequelModels::Block
        @db = db; @store = store
        @block_id = block[:id]
        @depth = block[:depth]

        @ver = block[:version]
        @prev_block = block[:prev_hash].reverse
        @mrkl_root = block[:mrkl_root].reverse
        @time = block[:time].to_i
        @bits = block[:bits]
        @nonce = block[:nonce]
        parents = db[:blk_tx].filter(:blk_id => block[:id])
          .order(:idx) rescue []
        parents.each do |parent|
          transaction = db[:tx][:id => parent[:tx_id]]
          @tx << store.get_tx(transaction[:hash].unpack("H*")[0])
        end
        recalc_block_hash
      end
      blk
    end

    def get_block_by_depth(depth)
      get_block(@db[:blk][:depth => depth][:hash].unpack("H*")[0]) rescue nil
    end

    def get_block_depth(blk_hash)
      @db[:blk][:hash => htb(blk_hash).to_sequel_blob][:depth]
    end

    def has_block(blk_hash)
      @db[:blk].where(:hash => htb(blk_hash).to_sequel_blob).exists == true
    end

    def has_tx(tx_hash)
      @db[:tx].where(:hash => htb(tx_hash).to_sequel_blob).exists == true
    end

    def store_tx(tx)
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
      })
    end

    def get_tx(tx_hash)
      transaction = @db[:tx][:hash => htb(tx_hash).to_sequel_blob]
      return nil  unless transaction
      tx = Bitcoin::Protocol::Tx.new(nil)
      db = @db; store = self
      tx.instance_eval do
        extend SequelModels::Tx
        @db = db; @store = store
        @id = transaction[:id]

        inputs = db[:txin].filter(:tx_id => transaction[:id])
          .order(:tx_idx)
        inputs.each do |input|
          add_in(@store.get_txin(input))
        end

        outputs = db[:txout].filter(:tx_id => transaction[:id])
          .order(:tx_idx)
        outputs.each do |output|
          add_out(@store.get_txout(output))
        end
        @ver = transaction[:version]
        @lock_time = transaction[:lock_time]
        @hash = hash_from_payload(@payload = to_payload)
      end
      tx
    end

    def get_txin(input)
      txin = Bitcoin::Protocol::TxIn.new
      txin.prev_out = input[:prev_out]
      txin.prev_out_index = input[:prev_out_index]
      txin.script_sig_length = input[:script_sig].bytesize
      txin.script_sig = input[:script_sig]
      txin.sequence = [input[:sequence]].pack("I")
      db = @db; store = self
      txin.instance_eval do
        extend SequelModels::TxIn
        @db = db; @store = store
        @id = input[:id]
        @tx_id = input[:tx_id]
      end
      txin
    end

    def get_txout(output)
      txout = Bitcoin::Protocol::TxOut.new
      txout.value = output[:value]
      txout.pk_script_length = output[:pk_script].bytesize
      txout.pk_script = output[:pk_script]
      db = @db; store = self
      txout.instance_eval do
        extend SequelModels::TxOut
        @db = db; @store = store
        @id = output[:id]
        @tx_id = output[:tx_id]
      end
      txout
    end

    def get_txouts_for_hash160(hash160)
      string = "OP_DUP OP_HASH160 #{hash160} OP_EQUALVERIFY OP_CHECKSIG"
      script = Bitcoin::Script.from_string(string)
      txouts = @db[:txout].filter(:pk_script => script.raw.to_sequel_blob).order(:id)
      txouts.map{|txout| get_txout(txout)}
    end

    def hth(bin); bin.unpack("H*")[0]; end
    def htb(hex); [hex].pack("H*"); end

  end

end
