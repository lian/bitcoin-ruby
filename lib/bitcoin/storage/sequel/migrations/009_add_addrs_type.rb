# Add column addr.type and correct the type for all p2sh addresses

Sequel.migration do

  up do

    @log.info { "Running migration #{__FILE__}" }

    puts "Fixing address types for #{self[:txout].where(type: 4).count} p2sh addresses..."

    add_column :addr, :type, :int, default: 0, null: false

    i = 0
    # iterate over all txouts with p2sh type
    self[:txout].where(type: 4).each do |txout|
      # find addr_txout mapping
      addr_txout = self[:addr_txout][txout_id: txout[:id]]

      # find currently linked address
      addr = self[:addr][id: addr_txout[:addr_id]]

      # skip if address type is already p2sh
      next i+=1  if addr[:type] == 1

      # if address has other txouts, that are not p2sh-type, we need a different one
      if self[:addr_txout].where(addr_id: addr[:id])
          .join(:txout, id: :txout_id).where("type != 4").any?

        # if there is already a corrected address
        if a = self[:addr][hash160: addr[:hash160], type: 1]
          # use the existing corrected address
          addr_id = a[:id]
        else
          # create new address with correct p2sh type
          addr_id = self[:addr].insert(hash160: addr[:hash160], type: 1)
        end

        # change mapping to point to new address
        self[:addr_txout].where(txout_id: txout[:id]).update(addr_id: addr_id)

      # if address has only this txout
      else
        # change to correct type
        self[:addr].where(id: addr[:id]).update(type: 1)
      end

      print "\r#{i}"; i+=1

    end
    puts

    add_index :addr, [:hash160, :type]

  end

end
