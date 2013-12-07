Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    next  if tables.include?(:tx)

    create_table :tx do
      primary_key :id
      column :hash, :varchar, :null => false, :unique => true, :index => true
      column :version, :bigint, :null => false
      column :lock_time, :bigint, :null => false
      column :coinbase, :bool, :null => false
      column :tx_size, :int, :null => false
    end

    create_table :blk_tx do
      column :blk_id, :int, :null => false, :index => true
      column :tx_id, :int, :null => false, :index => true
      column :idx, :int, :null => false
    end

    create_table :txin do
      primary_key :id
      column :tx_id, :int, :null => false, :index => true
      column :tx_idx, :int, :null => false
      column :script_sig, :varchar, :null => false
      column :prev_out, :varchar, :null => false, :index => true
      column :prev_out_index, :bigint, :null => false
      column :sequence, :bigint, :null => false
    end

    create_table :txout do
      primary_key :id
      column :tx_id, :int, :null => false, :index => true
      column :tx_idx, :int, :null => false
      column :pk_script, (@db.adapter_scheme == :postgres ? :bytea : :blob), :null => false
      column :value, :bigint
      column :type, :int, :null => false, :index => true
    end

  end

end
