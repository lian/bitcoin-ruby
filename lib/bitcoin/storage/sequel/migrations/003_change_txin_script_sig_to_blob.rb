Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    if adapter_scheme == :postgres
      add_column :txin, :tmp_script_sig, :bytea
      self[:txin].where.update("tmp_script_sig = script_sig::bytea")
      drop_column :txin, :script_sig
      add_column :txin, :script_sig, :bytea
      self[:txin].where.update("script_sig = tmp_script_sig")
      drop_column :txin, :tmp_script_sig
    end

  end

end
