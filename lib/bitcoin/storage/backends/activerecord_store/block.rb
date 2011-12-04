require 'pry'
module Bitcoin::Storage::Backends::ActiverecordStore

  class Block < ActiveRecord::Base

    include Base

    set_primary_key :block_id
    
    has_many :transactions_parents

    def transactions
      transactions_parents.sort_by(&:index_in_block).map(&:transaction)
    end

    # get block with given hash (in hex)
    def self.get hash
      Block.where("block_hash = decode(?, 'hex')", hash).first rescue nil
    end

    # get previous block
    def prev
      Block.where("block_hash = decode('#{hth(self.prev_block_hash)}', 'hex')").first
    end

    # get next block
    def next
      Block.where("prev_block_hash = decode('#{hth(self.block_hash)}', 'hex')").first
    end

    # get total value of all this block's outputs values
    def total_value
      connection.query("SELECT sum(outputs.value) FROM transactions_parents 
        LEFT JOIN transactions
            ON transactions.transaction_id = transactions_parents.transaction_id 
          LEFT JOIN outputs
              ON outputs.transaction_id = transactions.transaction_id
        WHERE block_id = '#{id}'")[0][0]
    end


    def to_hash
      {
        "ver" => version,
        "time" => when_created.to_i,
        "bits" => ((bits_head << 24) | bits_body),
        "nonce" => nonce,
        "prev_block" => Bitcoin::hth(prev_block_hash),
        "mrkl_root" => Bitcoin::hth(merkle),
        "tx" => transactions.map(&:to_hash)
      }
    end

    def to_protocol
      Bitcoin::Protocol::Block.from_hash(to_hash)
    end

    def self.from_protocol blk

      prev_block = get(hth(blk.prev_block.reverse))
      unless prev_block # || 
        unless blk.hash == Bitcoin::network[:genesis_hash]
          log.warn { "INVALID BLOCK: #{blk.hash}" }
          return nil
        end
      end

      block = new({
        :block_hash => blk.hash,
        :space => 0,
        :depth => (prev_block.depth + 1 rescue 0),
        :version => blk.ver,
        :prev_block_hash => (hth(prev_block.block_hash) rescue hth("\x00"*32)),
        :merkle => hth(blk.mrkl_root.reverse),
        :when_created => Time.at(blk.time),
        :when_found => Time.now,
        :nonce => blk.nonce,
        :span_left => 0,
        :span_right => 0,
        :bits_head => (blk.bits >> 24),
        :bits_body => (blk.bits & 0x00ffffff),
        :block_size => blk.payload.size,
      })

      blk.tx.each_with_index do |tx, idx|
        begin
          log.debug { "tx: #{tx.hash} (#{idx+1}/#{blk.tx.count})" }
          transaction = Transaction.from_protocol(tx)
          parent = TransactionsParent.new
          parent.transaction = transaction
          parent.index_in_block = idx
          block.transactions_parents << parent
        rescue
          log.error { "ERROR ADDING TX: #{tx.hash}" }
          p $!
          p *$@
          binding.pry
          File.open("./errors/#{Time.now.strftime("%H-%M-%S-")}-block-#{blk.hash}-tx-#{idx}", 'w') do |f|
            f.puts($!.inspect)
            $!.backtrace.each {|l| f.puts(l)}
            f.puts; f.puts; f.puts; f.puts
            f.write(blk.payload)
          end
        end
      end

      block
    end
      
    def save *args
      res = connection.query("INSERT INTO blocks (
            block_id,
            block_hash,
            space,
            depth,
            span_left,
            span_right,
            version,
            prev_block_hash,
            merkle,
            when_created,
            when_found,
            bits_head,
            bits_body,
            nonce,
            block_size
        ) VALUES (
            DEFAULT,
            decode('#{block_hash}', 'hex'),
            nextval('blocks_space_sequence'),
            '#{depth}',
            0,
            0,
            '#{version}',
            decode('#{prev_block_hash}', 'hex'),
            decode('#{merkle}', 'hex'),
            '#{when_created.to_s(:db)}',
            '#{when_found.to_s(:db)}',
            '#{bits_head}',
            '#{bits_body}',
            '#{nonce}',
            '#{block_size}'
        ) RETURNING block_id")


      transactions_parents.each do |parent|
        parent.block_id = res[0][0]
        parent.save
      end

      res[0][0]
    end
  end



end
