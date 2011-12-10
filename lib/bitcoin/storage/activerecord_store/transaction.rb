module Bitcoin::Storage::Backends::ActiverecordStore

  class Transaction < ActiveRecord::Base
    
    include Base

    set_primary_key :transaction_id

    has_one :transactions_parent
    has_one :block, :through => :transactions_parent
    has_many :inputs
    has_many :outputs

    def self.get hash
      Transaction.where("transaction_hash = decode(?, 'hex')", hash).first rescue nil
    end

    def output_value
      connection.query("SELECT sum(value) FROM outputs WHERE transaction_id = '#{transaction_id}'")[0][0]
    end

    # def verify
    #   inputs.each do |input|
    #     return false  unless input.verify
    #   end
    #   true
    # end

    def to_hash
      h = {
        "hash" => Bitcoin::hth(transaction_hash), "ver" => version,
        "vin_sz" => inputs.size, "vout_sz" => outputs.size,
        "lock_time" => locktime, "size" => transaction_size,
        "in" => inputs.map {|i|
          {'prev_out' => {
              'hash' => Bitcoin::hth(i.previous_output_hash),
              'n' => i.previous_output_index},
          'scriptSig' => Bitcoin::Script.new(i.script).to_string}
        },
        "out" => outputs.map {|o|
          {"value" => o.value,
            "scriptPubKey" => Bitcoin::Script.new(o.script).to_string}
        }
      }
      if (i=inputs[0]) && i.coinbase?
        h["in"][0] = {
          "prev_out" => {
            'hash' => Bitcoin::hth(i.previous_output_hash),
            'n' => i.previous_output_index},
          'coinbase' => i.script.unpack("H*")[0]
        }
      end
      h
    end

    def to_protocol
      Bitcoin::Protocol::Tx.from_hash(to_hash)
    end


    def self.from_protocol(tx)
      transaction = new({
        :transaction_hash => tx.hash,
        :version => tx.ver,
        :locktime => tx.lock_time,
        :coinbase => (tx.in.size == 1 && tx.in[0].coinbase?),
        :when_found => Time.now,
        :transaction_size => tx.payload.size,
      })

      tx.in.each_with_index do |txin, idx|
        log.debug { "txin: #{idx+1}/#{tx.in.count}" }
        input = Input.from_protocol(txin)
        input.index_in_parent = idx
        transaction.inputs << input
      end

      tx.out.each_with_index do |txout, idx|
        log.debug { "txout: #{idx+1}/#{tx.out.count}" }
        output = Output.from_protocol(txout)
        output.index_in_parent = idx
        transaction.outputs << output
      end
      transaction
    end

    def save *args
      res = connection.query("SELECT insert_transaction(
        decode('#{transaction_hash}', 'hex'), '#{version}', '#{locktime}', '#{coinbase}', '#{transaction_size}')")
      (inputs + outputs).each do |xput|
        xput.transaction_id = res[0][0]
        xput.save
      end
      res[0][0]
    end

    def is_coinbase?
      
    end

  end


end
