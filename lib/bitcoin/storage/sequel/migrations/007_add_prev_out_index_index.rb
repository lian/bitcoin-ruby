Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    # Naming seems to be different on different adapters and sequel's
    # "drop_index(:txin, :prev_out)" doesn't seem to be handling it correctly
    execute "DROP INDEX IF EXISTS txin_prev_out_idx;"
    execute "DROP INDEX IF EXISTS txin_prev_out_index;"

    add_index :txin, [:prev_out, :prev_out_index]

  end

end
