Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    create_table :utxo do
      primary_key :id
      column :tx_hash, String, null: false, index: true
      column :tx_idx, :int, null: false, index: true
      column :blk_id, :int, null: false, index: true
      column :pk_script, (@db.adapter_scheme == :postgres ? :bytea : :blob), null: false
      column :value, :bigint, null: false, index: true
    end

  end

end
