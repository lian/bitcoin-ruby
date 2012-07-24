Bitcoin.require_dependency :sequel, message:
  "Note: You will also need an adapter for your database like sqlite3, mysql2, postgresql"
require 'bitcoin/storage/sequel_store/sequel_migrations'

module Bitcoin::Storage::Backends

  # Storage backend using Sequel to connect to arbitrary SQL databases.
  # Inherits from StoreBase and implements its interface.
  class SequelStore < StoreBase


    # possible script types
    SCRIPT_TYPES = [:unknown, :pubkey, :hash160, :multisig, :p2sh]

    # sequel database connection
    attr_accessor :db

    include Bitcoin::Storage::Backends::SequelMigrations

    # create sequel store with given +config+
    def initialize config, *args
      @config = config
      connect
      super config, *args
    end

    # connect to database
    def connect
      {:sqlite => "sqlite3", :postgres => "pg", :mysql => "mysql",
      }.each do |adapter, name|
        if @config[:db].split(":").first == adapter.to_s
          Bitcoin.require_dependency name, gem: name
        end
      end

      @db = Sequel.connect(@config[:db])
      migrate
    end

    # reset database; delete all data
    def reset
      [:blk, :blk_tx, :tx, :txin, :txout].each {|table| @db[table].delete}
    end

    # persist given block +blk+ to storage.
    def persist_block blk, chain, depth
      @db.transaction do
        attrs = {
          :hash => htb(blk.hash).to_sequel_blob,
          :depth => depth,
          :chain => chain,
          :version => blk.ver,
          :prev_hash => blk.prev_block.reverse.to_sequel_blob,
          :mrkl_root => blk.mrkl_root.reverse.to_sequel_blob,
          :time => blk.time,
          :bits => blk.bits,
          :nonce => blk.nonce,
          :blk_size => blk.to_payload.bytesize,
        }
        existing = @db[:blk].filter(:hash => htb(blk.hash).to_sequel_blob)
        if existing.any?
          existing.update attrs
        else
          block_id = @db[:blk].insert(attrs)
          blk.tx.each_with_index do |tx, idx|
            tx_id = store_tx(tx)
            raise "Error saving tx #{tx.hash} in block #{blk.hash}"  unless tx_id
            @db[:blk_tx].insert({
                :blk_id => block_id,
                :tx_id => tx_id,
                :idx => idx,
              })
          end
        end
        begin
          @db[:blk].where(:prev_hash => htb(blk.hash).to_sequel_blob, :chain => ORPHAN).each do |b|
            log.debug { "re-org orphan #{hth(b[:hash])}" }
            begin
              store_block(get_block(hth(b[:hash])))
            rescue SystemStackError
              EM.defer { store_block(get_block(hth(b[:hash]))) }  if EM.reactor_running?
            end
          end
        rescue
          p $!
        end
        log.info { "block #{blk.hash} (#{depth}, #{['main', 'side', 'orphan'][chain]})" } 
        return depth, chain
      end
    end

    # update +attrs+ for block with given +hash+.
    def update_blocks updates
      @db.transaction do
        updates.each do |blocks, attrs|
          @db[:blk].filter(:hash => blocks.map{|h| htb(h).to_sequel_blob}).update(attrs)
        end
      end
    end

    # store transaction +tx+
    def store_tx(tx)
      @log.debug { "Storing tx #{tx.hash} (#{tx.to_payload.bytesize} bytes)" }
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
    rescue
      @log.warn { "Error storing tx: #{$!}" }
    end

    # store input +txin+
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

    # store output +txout+
    def store_txout(tx_id, txout, idx)
      script = Bitcoin::Script.new(txout.pk_script)
      txout_id = @db[:txout].insert({
          :tx_id => tx_id,
          :tx_idx => idx,
          :pk_script => txout.pk_script.to_sequel_blob,
          :value => txout.value,
          :type => SCRIPT_TYPES.index(script.type)
        })
      if script.is_hash160? || script.is_pubkey?
        store_addr(txout_id, script.get_hash160)
      elsif script.is_multisig?
        script.get_multisig_pubkeys.map do |pubkey|
          store_addr(txout_id, Bitcoin.hash160(pubkey.unpack("H*")[0]))
        end
      end
      txout_id
    end

    # store address +hash160+
    def store_addr(txout_id, hash160)
      addr = @db[:addr][:hash160 => hash160]
      addr_id = addr[:id]  if addr
      addr_id ||= @db[:addr].insert({:hash160 => hash160})
      @db[:addr_txout].insert({:addr_id => addr_id, :txout_id => txout_id})
    end

    # check if block +blk_hash+ exists
    def has_block(blk_hash)
      !!@db[:blk].where(:hash => htb(blk_hash).to_sequel_blob).get(1)
    end

    # check if transaction +tx_hash+ exists
    def has_tx(tx_hash)
      !!@db[:tx].where(:hash => htb(tx_hash).to_sequel_blob).get(1)
    end

    # get head block (highest block from the MAIN chain)
    def get_head
      wrap_block(@db[:blk].filter(:chain => MAIN).order(:depth).last)
    end

    # get depth of MAIN chain
    def get_depth
      return -1  unless get_head
      @db[:blk][:hash => htb(get_head.hash).to_sequel_blob][:depth]
    end

    # get block for given +blk_hash+
    def get_block(blk_hash)
      wrap_block(@db[:blk][:hash => htb(blk_hash).to_sequel_blob])
    end

    # get block by given +depth+
    def get_block_by_depth(depth)
      wrap_block(@db[:blk][:depth => depth, :chain => MAIN])
    end

    # get block by given +prev_hash+
    def get_block_by_prev_hash(prev_hash)
      wrap_block(@db[:blk][:prev_hash => htb(prev_hash).to_sequel_blob])
    end

    # get block by given +tx_hash+
    def get_block_by_tx(tx_hash)
      tx = @db[:tx][:hash => htb(tx_hash).to_sequel_blob]
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
      wrap_tx(@db[:tx][:hash => htb(tx_hash).to_sequel_blob])
    end

    # get transaction by given +tx_id+
    def get_tx_by_id(tx_id)
      wrap_tx(@db[:tx][:id => tx_id])
    end

    # get corresponding Models::TxIn for the txout in transaction
    # +tx_hash+ with index +txout_idx+
    def get_txin_for_txout(tx_hash, txout_idx)
      tx_hash = htb(tx_hash).reverse.to_sequel_blob
      wrap_txin(@db[:txin][:prev_out => tx_hash, :prev_out_index => txout_idx])
    end

    # get corresponding Models::TxOut for +txin+
    def get_txout_for_txin(txin)
      tx = @db[:tx][:hash => txin.prev_out.reverse.to_sequel_blob]
      return nil  unless tx
      wrap_txout(@db[:txout][:tx_idx => txin.prev_out_index, :tx_id => tx[:id]])
    end

    # get all Models::TxOut matching given +script+
    def get_txouts_for_pk_script(script)
      txouts = @db[:txout].filter(:pk_script => script.to_sequel_blob).order(:id)
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
        txouts.select!{|o| o.get_tx.get_block.chain == MAIN rescue false }
      end
      txouts
    end

    # get all unconfirmed Models::TxOut
    def get_unconfirmed_tx
      @db[:unconfirmed].map{|t| wrap_tx(t)}
    end

    # wrap given +block+ into Models::Block
    def wrap_block(block)
      return nil  unless block

      data = {:id => block[:id], :depth => block[:depth], :chain => block[:chain]}
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

    # wrap given +transaction+ into Models::Transaction
    def wrap_tx(transaction)
      return nil  unless transaction

      parents = @db[:blk_tx].where(:tx_id => transaction[:id])
      parent = parents.map{|m|@db[:blk][:id => m[:blk_id]]}.sort_by {|b| b[:chain]}.first
      block_id = parent ? parent[:id] : nil
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

    # wrap given +input+ into Models::TxIn
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


    def hth(bin); bin.unpack("H*")[0]; end
    def htb(hex); [hex].pack("H*"); end

  end

end
