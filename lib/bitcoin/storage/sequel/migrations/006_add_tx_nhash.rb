Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    def process_block blk
      print "\r#{blk.hash} - #{blk.depth}"
      blk.tx.each do |tx|
        self[:tx].where(hash: tx.hash.htb.blob).update(nhash: tx.nhash.htb.blob)
      end
    end

    if $stdin.tty?
      print "Do you want to build an index for normalized tx hashes? (~1GB) (y/N) "
      if $0 =~ /spec/ || $stdin.gets.chomp == "y"
        puts "Building normalized hash index..."

        add_column :tx, :nhash, :bytea

        if blk = @store.get_block_by_depth(0)
          process_block(blk)
          while blk = blk.get_next_block
            process_block(blk)
          end
        end

        add_index :tx, :nhash

      end
    end
  end

end
