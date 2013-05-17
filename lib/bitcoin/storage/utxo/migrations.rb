module Bitcoin::Storage::Backends::UtxoMigrations

  def migrate
    unless @db.tables.include?(:blk)
      @db.create_table :blk do
        primary_key :id
        column :hash, :bytea, :null => false, :unique => true, :index => true
        column :depth, :int, :null => false, :index => true
        column :version, :bigint, :null => false
        column :prev_hash, :bytea, :null => false, :index => true
        column :mrkl_root, :bytea, :null => false
        column :time, :bigint, :null => false
        column :bits, :bigint, :null => false
        column :nonce, :bigint, :null => false
        column :blk_size, :int, :null => false
        column :chain, :int, :null => false
        column :work, :bytea, :index => true
      end
    end

    unless @db.tables.include?(:utxo)
      @db.create_table :utxo do
        primary_key :id
        column :tx_hash, String, null: false, index: true
        column :tx_idx, :int, null: false, index: true
        column :blk_id, :int, null: false, index: true
        column :pk_script, :bytea, null: false
        column :value, :bigint, null: false, index: true
      end
    end

    unless @db.tables.include?(:addr)
      @db.create_table :addr do
        primary_key :id
        column :hash160, :bytea, null: false, index: true
        column :pubkey, :bytea, index: true
      end
    end

    unless @db.tables.include?(:addr_txout)
      @db.create_table :addr_txout do
        column :addr_id, :int, null: false, index: true
        column :txout_id, :int, null: false, index: true
      end
    end

    unless @db.tables.include?(:names)
      @db.create_table :names do
        column :txout_id, :int, :null => false, :index => true
        column :hash, :bytea, :index => true
        column :name, :bytea, :index => true
        column :value, :bytea
      end
    end

  end

end
