module Bitcoin::Storage::Backends::ActiverecordStore

  class Input < ActiveRecord::Base
    
    include Base

    set_primary_key :input_id
    
    belongs_to :transaction
    

    def previous_output
      return nil  if transaction.coinbase
      ptx = Transaction.get(Bitcoin::hth(previous_output_hash))
      Output.where("transaction_id = '#{ptx.transaction_id}'
        AND index_in_parent = '#{previous_output_index}'").first
    end

    # def verify
    #   return nil  if transaction.coinbase
    #   unless previous_output.transaction.coinbase
    #     previous_output.transaction.verify
    #   end
    #   inscript = Bitcoin::Script.new(script)
    #   outscript = Bitcoin::Script.new(previous_output.script)
    #   outscript.run(inscript.chunks) do |*args|
    #     # OP_CHECKSIG always true
    #     true
    #   end
    # end

    def self.from_protocol txin
      new({
            :script => txin[3],
            :previous_output_hash => txin[0].reverse,
            :previous_output_index => txin[1],
            :sequence => txin[4].unpack("I")[0]
          })
    end

    def save *args
      res = connection.query("INSERT INTO inputs
        (input_id, transaction_id, index_in_parent,
        script, previous_output_hash, previous_output_index, sequence)
        VALUES (DEFAULT, '#{transaction_id}', '#{index_in_parent}',
        decode('#{Bitcoin::hth(script)}', 'hex'),
        decode('#{Bitcoin::hth(previous_output_hash)}', 'hex'),
        '#{previous_output_index}', '#{sequence}') \
        RETURNING input_id")
      res[0]
    end
    
  end

end
