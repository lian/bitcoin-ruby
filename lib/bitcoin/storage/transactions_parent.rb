module Bitcoin::Storage

  class TransactionsParent < ActiveRecord::Base
    
    belongs_to :block
    belongs_to :transaction
    
    def save *args
      transaction_id = transaction.save(*args)
      res = connection.query("INSERT INTO transactions_parents
        (transaction_id, block_id, index_in_block) VALUES
        ('#{transaction_id}', '#{block_id}', '#{index_in_block}')")
    end

  end

end
