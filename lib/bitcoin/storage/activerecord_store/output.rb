module Bitcoin::Storage::Backends::ActiverecordStore

  class Output < ActiveRecord::Base
    
    include Base

    set_primary_key :output_id

    belongs_to :transaction

    def next_input
      res = connection.query("SELECT input_id FROM inputs WHERE
        previous_output_hash = decode('#{Bitcoin::hth(transaction.transaction_hash)}', 'hex') AND
        previous_output_index = '#{index_in_parent}'")
      Input.find(res[0][0]) rescue nil
    end

    def value
      attributes['value']
    end

    def self.from_protocol txout
      raise ArgumentError.new("value too high: #{txout[0]}")  if txout[0] > 21e14
      new({
        :value => txout[0] / 1e8,
        :script => txout[2],
      })
    end

    def save *args
      res = connection.query("INSERT INTO outputs (
        output_id, transaction_id, index_in_parent, script, value)
        VALUES (DEFAULT, '#{transaction_id}', '#{index_in_parent}',
        decode('#{Bitcoin::hth(script)}', 'hex'), '#{attributes['value']}')
        RETURNING output_id")
      return res[0]
    end

  end

end
