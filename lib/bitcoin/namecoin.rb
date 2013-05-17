# encoding: ascii-8bit

module Bitcoin::Namecoin

  module Script

    def self.included(base)
      base.constants.each {|c| const_set(c, base.const_get(c)) unless constants.include?(c) }
      base.class_eval do

        # get the hash160 for this hash160, namecoin or pubkey script
        def get_hash160
          return @chunks[2..-3][0].unpack("H*")[0]  if is_hash160?
          return @chunks[-3].unpack("H*")[0]        if is_namecoin?
          return Bitcoin.hash160(get_pubkey)        if is_pubkey?
        end

        # get all addresses this script corresponds to (if possible)
        def get_addresses
          return [get_pubkey_address]    if is_pubkey?
          return [get_hash160_address]   if is_hash160? || is_namecoin?
          return get_multisig_addresses  if is_multisig?
        end

        # get type of this tx
        def type
          if is_name_new?;            :name_new
          elsif is_name_firstupdate?; :name_firstupdate
          elsif is_name_update?;      :name_update
          elsif is_hash160?;          :hash160
          elsif is_pubkey?;           :pubkey
          elsif is_multisig?;         :multisig
          elsif is_p2sh?;             :p2sh
          else;                       :unknown
          end
        end

        # is namecoin name_new script
        # OP_1 name_hash OP_2DROP <hash160_script>
        def is_name_new?
          return false  if @chunks.size < 8
          [-8, -6, -5, -4, -2, -1].map {|i| @chunks[i] } ==
            [OP_1, OP_2DROP, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG]
        end

        # is namecoin name_firstupdate script
        # OP_2 name rand value OP_2DROP OP_2DROP <hash160_script>
        def is_name_firstupdate?
          return false  if @chunks.size < 11
          [-11, -7, -6, -5, -4, -2, -1].map {|i| @chunks[i] } ==
            [82, OP_2DROP, OP_2DROP, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG]
        end

        # is namecoin name_update script
        # OP_3 name value OP_2DROP OP_DROP <hash160_script>
        def is_name_update?
          return false  if @chunks.size < 10
          [-10, -7, -6, -5, -4, -2, -1].map {|i| @chunks[i] } ==
            [83, OP_2DROP, OP_DROP, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG]
        end

        # is any kind of namecoin script
        def is_namecoin?
          is_name_new? || is_name_firstupdate? || is_name_update?
        end

        # get the name_hash of a namecoin name_new script
        def get_namecoin_hash
          return @chunks[-7].hth  if is_name_new?
          if is_name_firstupdate?
            name = @chunks[-10].to_s.hth
            rand = @chunks[-9].to_s.hth
            return Bitcoin.hash160(rand + name)
          end
        rescue
          nil
        end

        # get the name of a namecoin name_firstupdate or name_update script
        def get_namecoin_name
          return @chunks[-10]  if is_name_firstupdate?
          return @chunks[-9]  if is_name_update?
        end

        # get the value of a namecoin name_firstupdate or name_update script
        def get_namecoin_value
          @chunks[-8]  if is_name_firstupdate? || is_name_update?
        end

        # generate name_new tx for given +name+ and +address+.
        # the +caller+ should be the object that creates the script.
        # it gets the used random value passed to #set_rand.
        # OP_1 name_hash OP_2DROP <hash160_script>
        def self.to_name_new_script(caller, name, address)
          rand = rand(2**64).to_s(16).rjust(16, '0')
          name_hash = Bitcoin.hash160(rand + name.unpack("H*")[0])
          caller.set_rand rand # TODO: this is still ugly
          [ [ "51", "14",   name_hash, "6d" ].join ].pack("H*") + to_address_script(address)
        end

        # generate name_firstupdate tx for given +name+, +rand+, +value+ and +address+.
        # OP_2 name rand value OP_2DROP OP_2DROP <hash160_script>
        def self.to_name_firstupdate_script(name, rand, value, address)
          [ [ "52", name.bytesize.to_s(16).rjust(2, '0'), name.hth,
              rand.htb.bytesize.to_s(16).rjust(2, '0'), rand,
              value.bytesize.to_s(16).rjust(2, '0'), value.hth,
              "6d", "6d" ].join ].pack("H*") + to_address_script(address)
        end

        # generate name_update script for given +name+, +value+ and +address+.
        # OP_3 name value OP_2DROP OP_DROP <hash160_script>
        def self.to_name_update_script(name, value, address)
          [ [ "53", name.bytesize.to_s(16).rjust(2, '0'), name.hth,
              value.bytesize.to_s(16).rjust(2, '0'), value.hth,
              "6d", "75" ].join ].pack("H*") + to_address_script(address)
        end

      end
    end

  end

  module Storage

    def self.included(base)
      base.constants.each {|c| const_set(c, base.const_get(c)) unless constants.include?(c) }
      base.class_eval do

        # if this is a namecoin script, update the names index
        def store_name(script, txout_id)
          if script.type == :name_new
            log.info { "name_new #{script.get_namecoin_hash}" }
            @db[:names].insert({
              :txout_id => txout_id,
              :hash => script.get_namecoin_hash })
          elsif script.type == :name_firstupdate
            name_hash = script.get_namecoin_hash
            name_new = @db[:names].where(:hash => name_hash).order(:txout_id).first
            if self.class.name =~ /UtxoStore/
              txout = @db[:utxo][id: name_new[:txout_id]] if name_new
              blk = @db[:blk][id: txout[:blk_id]]  if txout
            else
              txout = @db[:txout][id: name_new[:txout_id]] if name_new
              tx = @db[:tx][id: txout[:tx_id]] if txout
              blk_tx = @db[:blk_tx][tx_id: tx[:id]]  if tx
              blk = @db[:blk][id: blk_tx[:blk_id]] if blk_tx
            end

            unless name_new && blk && blk[:chain] == 0
              log.warn { "name_new not found: #{name_hash}" }
              return nil
            end

            unless blk[:depth] <= get_depth - NAMECOIN_FIRSTUPDATE_LIMIT
              log.warn { "name_new not yet valid: #{name_hash}" }
              return nil
            end

            log.info { "#{script.type}: #{script.get_namecoin_name}" }
            @db[:names].where(:txout_id => name_new[:txout_id], :name => nil).update({
              :name => script.get_namecoin_name.to_s.blob })
            @db[:names].insert({
              :txout_id => txout_id,
              :hash => name_hash,
              :name => script.get_namecoin_name.to_s.blob,
              :value => script.get_namecoin_value.to_s.blob })
          elsif script.type == :name_update
            log.info { "#{script.type}: #{script.get_namecoin_name}" }
            @db[:names].insert({
              :txout_id => txout_id,
              :name => script.get_namecoin_name.to_s.blob,
              :value => script.get_namecoin_value.to_s.blob })
          end
        end

        def name_show name
          names = @db[:names].where(:name => name.blob).order(:txout_id).reverse
          return nil  unless names.any?
          wrap_name(names.first)
        end

        def name_history name
          history = @db[:names].where(:name => name.blob)
            .where("value IS NOT NULL").order(:txout_id).map {|n| wrap_name(n) }
          history.select! {|n| n.get_tx.blk_id }  unless self.class.name =~ /Utxo/ 
          history
        end

        def get_name_by_txout_id txout_id
          wrap_name(@db[:names][:txout_id => txout_id])
        end

        def wrap_name(data)
          return nil  unless data
          Bitcoin::Storage::Models::Name.new(self, data)
        end

      end
    end

  end

end
