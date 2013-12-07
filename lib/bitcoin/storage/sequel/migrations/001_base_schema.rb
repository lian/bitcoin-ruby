Sequel.migration do


  up do

    @log.info { "Running migration #{__FILE__}" }

    binary = adapter_scheme == :postgres ? :bytea : :varchar

    alter_table :schema_info do
      add_column :magic, :varchar # network magic-head
      add_column :backend, :varchar # storage backend
    end

    next  if tables.include?(:blk)

    create_table :blk do
      primary_key :id
      column :hash, binary, :null => false, :unique => true, :index => true
      column :depth, :int, :null => false, :index => true
      column :version, :bigint, :null => false
      column :prev_hash, binary, :null => false, :index => true
      column :mrkl_root, binary, :null => false
      column :time, :bigint, :null => false
      column :bits, :bigint, :null => false
      column :nonce, :bigint, :null => false
      column :blk_size, :int, :null => false
      column :chain, :int, :null => false
      column :work, binary, :index => true
      column :aux_pow, binary
    end

    create_table :addr do
      primary_key :id
      column :hash160, String, :null => false, :index => true
    end

    create_table :addr_txout do
      column :addr_id, :int, :null => false, :index => true
      column :txout_id, :int, :null => false, :index => true
    end

    create_table :names do
      column :txout_id, :int, :null => false, :index => true
      column :hash, binary, :index => true
      column :name, binary, :index => true
      column :value, binary
    end

  end

end
