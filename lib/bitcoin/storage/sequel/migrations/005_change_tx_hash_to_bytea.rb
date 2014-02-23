Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    if adapter_scheme == :postgres
      execute "DROP VIEW unconfirmed" # hasn't been used for a while now
      execute "ALTER TABLE tx ALTER COLUMN hash TYPE bytea USING hash::bytea"
    end

  end

end
