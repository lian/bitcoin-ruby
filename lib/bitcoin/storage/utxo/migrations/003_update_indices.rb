Sequel.migration do
  up do
    @log.info { "Running migration #{__FILE__}" }

    alter_table :utxo do
      # This is used when deleting spent uxto rows
      add_index([:tx_hash, :tx_idx])

      # These don't seem to be necessary
      drop_index :tx_idx
      drop_index :value
    end
  end
end
