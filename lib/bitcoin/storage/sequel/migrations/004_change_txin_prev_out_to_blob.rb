Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    if adapter_scheme == :postgres
      add_column :txin, :tmp_prev_out, :bytea
      self[:txin].where.update("tmp_prev_out = prev_out::bytea")
      drop_column :txin, :prev_out
      add_column :txin, :prev_out, :bytea, index: true
      self[:txin].where.update("prev_out = tmp_prev_out")
      drop_column :txin, :tmp_prev_out
    end

  end

end
