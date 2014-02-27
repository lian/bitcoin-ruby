# encoding: ascii-8bit

# This module includes (almost) everything necessary to add namecoin support
# to bitcoin-ruby. When switching to a :namecoin network, it will load its
# functionality into the Script class and the Storage backend.
# The only things not included here should be parsing the AuxPow, which is
# done in Protocol::Block directly, and passing the txout to #store_name from
# the storage backend.
module Bitcoin::Namecoin

  def self.load
    Bitcoin::Script.class_eval { include Script }
    Bitcoin::Storage::Backends::StoreBase.class_eval { include Storage::Backend }
    Bitcoin::Storage::Models.class_eval { include Storage::Models }
  end

  # name_new must have 12 confirmations before corresponding name_firstupdate is valid.
  FIRSTUPDATE_LIMIT = 12

  # number of blocks after which a name expires.
  EXPIRATION_DEPTH = 36000

  # Namecoin-specific Script methods for parsing and creating of namecoin scripts,
  # as well as methods to extract address, name_hash, name and value.
  module Script

    def self.included(base)
      base.constants.each {|c| const_set(c, base.const_get(c)) unless constants.include?(c) }
      base.class_eval do

        # get the hash160 for this hash160, namecoin or pubkey script
        def get_hash160
          return @chunks[2..-3][0].unpack("H*")[0]  if is_hash160?
          return @chunks[-3].unpack("H*")[0]        if is_namecoin?
          return @chunks[-2].unpack("H*")[0]        if is_p2sh?
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

  # Namecoin-specific storage methods.
  # The storage backend only needs to check txout scripts with #is_namecoin? and
  # pass them to #store_name.
  # TODO: move rules into Validation
  module Storage

    module Backend

      def self.included(base)
        base.constants.each {|c| const_set(c, base.const_get(c)) unless constants.include?(c) }
        base.class_eval do

          # if this is a namecoin script, update the names index
          def store_name(script, txout_id)
            if script.type == :name_new
              log.debug { "name_new #{script.get_namecoin_hash}" }
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
                log.debug { "name_new not found: #{name_hash}" }
                return nil
              end

              unless blk[:depth] <= get_depth - Bitcoin::Namecoin::FIRSTUPDATE_LIMIT
                log.debug { "name_new not yet valid: #{name_hash}" }
                return nil
              end

              log.debug { "#{script.type}: #{script.get_namecoin_name}" }
              @db[:names].where(:txout_id => name_new[:txout_id], :name => nil).update({
                :name => script.get_namecoin_name.to_s.to_sequel_blob })
              @db[:names].insert({
                :txout_id => txout_id,
                :hash => name_hash,
                :name => script.get_namecoin_name.to_s.to_sequel_blob,
                :value => script.get_namecoin_value.to_s.to_sequel_blob })
            elsif script.type == :name_update
              log.debug { "#{script.type}: #{script.get_namecoin_name}" }
              @db[:names].insert({
                :txout_id => txout_id,
                :name => script.get_namecoin_name.to_s.to_sequel_blob,
                :value => script.get_namecoin_value.to_s.to_sequel_blob })
            end
          end

          def name_show name
            names = @db[:names].where(:name => name.to_sequel_blob).order(:txout_id).reverse
            return nil  unless names.any?
            wrap_name(names.first)
          end
          alias :get_name :name_show

          def name_history name
            history = @db[:names].where(:name => name.to_sequel_blob)
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

    module Models

      class Name

        attr_reader :store, :txout_id, :hash, :name, :value

        def initialize store, data
          @store = store
          @txout_id = data[:txout_id]
          @hash = data[:hash]
          @name = data[:name]
          @value = data[:value]
        end

        def get_txout
          if @txout_id.is_a?(Array)
            @store.get_tx(@txout_id[0]).out[@txout_id[1]]
          else
            @store.get_txout_by_id(@txout_id)
          end
        end

        def get_address
          get_txout.get_address
        end

        def get_tx
          get_txout.get_tx rescue nil
        end

        def get_block
          get_tx.get_block rescue nil
        end

        def expires_in
          Bitcoin::Namecoin::EXPIRATION_DEPTH - (@store.get_depth - get_block.depth) rescue nil
        end

        def as_json(opts = {})
          { name: @name, value: @value, txid: get_tx.hash,
                                 address: get_address, expires_in: expires_in }
        end

      end

    end

  end

end
