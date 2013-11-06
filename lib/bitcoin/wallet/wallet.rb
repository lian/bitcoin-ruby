# encoding: ascii-8bit

Bitcoin.require_dependency :eventmachine, exit: false

# The wallet implementation consists of several concepts:
# Wallet::             the high-level API used to manage a wallet
# SimpleKeyStore::     key store to manage keys/addresses/labels
# SimpleCoinSelector:: coin selector to find unspent outputs to use when creating tx
module Bitcoin::Wallet

  # A wallet manages a set of keys (through a +keystore+), can
  # list transactions/balances for those keys (using a Storage backend for
  # blockchain data).
  # It can also create transactions with various kinds of outputs and
  # connect with a CommandClient to relay those transactions through a node.
  #
  # TODO: new tx notification, keygenerators, keystore cleanup
  class Wallet

    include Bitcoin
    include Builder

    # the keystore (SimpleKeyStore) managing keys/addresses/labels
    attr_reader :keystore

    # the Storage which holds the blockchain
    attr_reader :storage

    # open wallet with given +storage+ Storage backend, +keystore+ SimpleKeyStore
    # and +selector+ SimpleCoinSelector
    def initialize storage, keystore, selector = SimpleCoinSelector
      @storage = storage
      @keystore = keystore
      @selector = selector
      @callbacks = {}

      @keystore.keys.each {|key| @storage.add_watched_address(key[:addr]) }
      # connect_node  if defined?(EM)

    end

    def connect_node
      return  unless EM.reactor_running?
      host, port = "127.0.0.1", 9999
      @node = Network::CommandClient.connect(host, port, self, @storage) do
        on_connected { request :monitor, "block", "tx" }
        on_block do |block, depth|
          EM.defer do
            block['tx'].each do |tx|
              relevant, tx = @args[0].check_tx(tx['hash'])
              @args[0].callback(:tx, :confirmed, tx)  if relevant
            end
          end
        end

        on_tx do |response|
          EM.defer do
            relevant, tx = @args[0].check_tx(response['hash'])
            @args[0].callback(:tx, relevant, tx)  if relevant
          end
        end
      end
    end

    def check_tx tx_hash
      relevant = false
      addrs = addrs
      tx = @storage.get_tx(tx_hash)
      unless tx
        log.warn { "Received tx #{response['hash']} but not found in storage" }
        binding.pry
        return false
      end
      addrs = @keystore.keys.map {|k| k[:addr] }
      tx.out.each do |txout|
        return :incoming, tx  if (txout.get_addresses & addrs).any?
      end
      tx.in.each do |txin|
        next unless  prev_out = txin.get_prev_out
        return :outgoing, tx  if (prev_out.get_addresses & addrs).any?
      end
      return false
    end

    def log
      return @log  if @log
      @log = Logger.create("wallet")
      @log.level = :debug
      @log
    end

    # call the callback specified by +name+ passing in +args+
    def callback name, *args
      cb = @callbacks[name.to_sym]
      return  unless cb
      log.debug { "callback: #{name}" }
      cb.call(*args)
    end

    # register callback methods
    def method_missing(name, *args, &block)
      if name =~ /^on_/
        @callbacks[name.to_s.split("on_")[1].to_sym] = block
        log.debug { "callback #{name} registered" }
      else
        super(name, *args)
      end
    end

    # get all Storage::Models::TxOut concerning any address from this wallet
    def get_txouts(unconfirmed = false)
      txouts = @keystore.keys.map {|k|
        @storage.get_txouts_for_address(k[:addr])}.flatten.uniq
      (unconfirmed || @storage.class.name =~ /Utxo/) ? txouts : txouts.select {|o| !!o.get_tx.get_block}
    end

    # get total balance for all addresses in this wallet
    def get_balance(unconfirmed = false)
      values = get_txouts(unconfirmed).select{|o| !o.get_next_in}.map(&:value)
      ([0] + values).inject(:+)
    end

    # list all addresses in this wallet
    def addrs
      @keystore.keys.map{|k| k[:addr]}
    end

    # add +key+ to wallet
    def add_key key
      @keystore.add_key(key)
      @storage.add_watched_address(key[:addr])
    end

    # set label for key +old+ to +new+
    def label old, new
      @keystore.label_key(old, new)
    end

    # set +flag+ for key +name+ to +value+
    def flag name, flag, value
      @keystore.flag_key(name, flag, value)
    end

    # list all keys along with their balances
    def list
      @keystore.keys.map do |key|
        [key, @storage.get_balance(Bitcoin.hash160_from_address(key[:addr]))]
      end
    end

    # create new key and return its address
    def get_new_addr
      key = @keystore.new_key
      @storage.add_watched_address(key.addr)
      key.addr
    end

    def import_key base58, label = nil
      key = @keystore.import(base58, label)
      @storage.add_watched_address(key.addr)
      key.addr
    end

    def rescan
      @storage.rescan
    end

    # get SimpleCoinSelector with txouts for this wallet
    def get_selector
      @selector.new(get_txouts)
    end

    # create a transaction with given +outputs+, +fee+ and +change_policy+.
    #
    # outputs are of the form
    #  [<type>, <recipients>, <value>]
    # examples:
    #  [:address, <addr>, <value>]
    #  [:multisig, 2, 3, <addr>, <addr>, <addr>, <value>]
    #
    # inputs are selected automatically by the SimpleCoinSelector.
    #
    # change_policy controls where the change_output is spent to.
    # see #get_change_addr
    def new_tx outputs, fee = 0, change_policy = :back
      output_value = outputs.map{|o| o[-1] }.inject(:+)

      prev_outs = get_selector.select(output_value)
      raise "Insufficient funds."  if !prev_outs
      if Bitcoin.namecoin?
        prev_out = nil
        outputs.each do |out|
          if out[0] == :name_firstupdate
            name_hash = Bitcoin.hash160(out[2] + out[1].hth)
            break  if prev_out = get_txouts.find {|o|
              o.type == :name_new && o.script.get_namecoin_hash == name_hash }
          elsif out[0] == :name_update
            break  if prev_out = storage.name_show(out[1]).get_txout rescue nil
          end
        end
        if outputs.find{|o| [:name_firstupdate, :name_update].include?(o[0]) }
          raise "previous name tx not found in wallet."  unless prev_out
          prev_outs += [prev_out]
        end
      end

      input_value = prev_outs.map(&:value).inject(:+)
      raise "Insufficient funds."  unless input_value >= (output_value + fee)

      tx = build_tx do |t|
        t.version 0x7100  if Bitcoin.namecoin? && outputs.find {|o| o[0].to_s =~ /^name_/ }
        outputs.each do |type, *addrs, value|
          t.output do |o|
            o.value value
            o.script do |s|
              s.type type
              s.recipient *addrs
            end
          end
        end

        change_value = input_value - output_value - fee
        if change_value > 0
          change_addr = get_change_addr(change_policy, prev_outs.sample.get_address)
          t.output do |o|
            o.value change_value
            o.script do |s|
              s.type :address
              s.recipient change_addr
            end
          end
        end

        prev_outs.each_with_index do |prev_out, idx|
          t.input do |i|
            prev_tx = prev_out.get_tx
            i.prev_out prev_tx
            i.prev_out_index prev_tx.out.index(prev_out)
            pk_script = Script.new(prev_out.pk_script)
            if pk_script.is_pubkey? || pk_script.is_hash160? || pk_script.is_namecoin?
              i.signature_key @keystore.key(prev_out.get_address)[:key]
            elsif pk_script.is_multisig?
              raise "multisig not implemented"
            end
          end
        end
      end

      # TODO: spend multisig outputs again
      # TODO: verify signatures
      raise "Payload Error"  unless P::Tx.new(tx.to_payload).to_payload == tx.to_payload

      tx
    end

    protected

    # get address to send change output to.
    # +policy+ controls which address is chosen:
    # first:: send to the first key in the wallets keystore
    # random:: send to a random key from the wallets keystore
    # new:: send to a new key generated in the wallets keystore
    # back:: send to the address given as +in_addr+
    def get_change_addr(policy, in_addr)
      case policy
      when :first
        @keystore.keys[0].addr
      when :random
        @keystore.keys.sample.addr
      when :new
        @keystore.new_key.addr
      when :back
        in_addr
      else
        policy
      end
    end

  end

end
