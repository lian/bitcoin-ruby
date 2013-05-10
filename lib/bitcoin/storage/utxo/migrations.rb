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
        column :tx_hash, :bytea, null: false, index: true
        column :tx_idx, :int, null: false, index: true
        column :blk_id, :int, null: false, index: true
        column :pk_script, :bytea, null: false
        column :value, :bigint, null: false, index: true
      end
    end

  end

end
