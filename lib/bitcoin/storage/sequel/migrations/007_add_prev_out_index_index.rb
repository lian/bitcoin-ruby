Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    if adapter_scheme == :postgres
      execute "DROP INDEX IF EXISTS txin_prev_out_idx;"
      execute "DROP INDEX IF EXISTS txin_prev_out_index;"
    else
      drop_index(:txin, :prev_out)
    end

    add_index :txin, [:prev_out, :prev_out_index]

  end

end
