module Bitcoin::Storage::Backends::SequelMigrations

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
      end
    end

    unless @db.tables.include?(:tx)
      @db.create_table :tx do
        primary_key :id
        column :hash, :bytea, :null => false, :unique => true, :index => true
        column :version, :bigint, :null => false
        column :lock_time, :bigint, :null => false
        column :coinbase, :bool, :null => false
        column :tx_size, :int, :null => false
      end
    end

    unless @db.tables.include?(:blk_tx)
      @db.create_table :blk_tx do
        column :blk_id, :int, :null => false, :index => true
        column :tx_id, :int, :null => false, :index => true
        column :idx, :int, :null => false
      end
    end

    unless @db.tables.include?(:txin)
      @db.create_table :txin do
        primary_key :id
        column :tx_id, :int, :null => false, :index => true
        column :tx_idx, :int, :null => false
        column :script_sig, :bytea, :null => false
        column :prev_out, :bytea, :null => false, :index => true
        column :prev_out_index, :bigint, :null => false
        column :sequence, :bigint, :null => false
      end
    end

    unless @db.tables.include?(:txout)
      @db.create_table :txout do
        primary_key :id
        column :tx_id, :int, :null => false, :index => true
        column :tx_idx, :int, :null => false
        column :pk_script, :bytea, :null => false, :index => true
        column :value, :bigint
        column :hash160, String
        index :hash160
      end
    end
  end

end
