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

    # the keystore (SimpleKeyStore) managing keys/addresses/labels
    attr_reader :keystore

    # the Storage which holds the blockchain
    attr_reader :storage

    # open wallet with given +storage+ Storage backend, +keystore+ SimpleKeyStore
    # and +selector+ SimpleCoinSelector
    def initialize storage, keystore, selector
      @storage = storage
      @keystore = keystore
      @selector = selector
      @callbacks = {}
      connect_node  if defined?(EM)
    end

    def connect_node
      return  unless EM.reactor_running?
      host, port = "127.0.0.1", 9999
      @node = Bitcoin::Network::CommandClient.connect(host, port, self, @storage) do
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
            p "tx: #{response['hash']}"
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
      @log = Bitcoin::Logger.create("wallet")
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
      unconfirmed ? txouts : txouts.select {|o| !!o.get_tx.get_block}
    end

    # get total balance for all addresses in this wallet
    def get_balance
      values = get_txouts.select{|o| !o.get_next_in}.map(&:value)

      ([0] + values).inject(:+)
    end

    # list all addresses in this wallet
    def addrs
      @keystore.keys.map{|k| k[:key].addr}
    end

    # add +key+ to wallet
    def add_key key
      @keystore.add_key(key)
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
      @keystore.new_key.addr
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
    def tx outputs, fee = 0, change_policy = :back
      output_value = outputs.map{|o|o[-1]}.inject(:+)

      prev_outs = get_selector.select(output_value)
      return nil  if !prev_outs

      tx = Bitcoin::Protocol::Tx.new(nil)

      input_value = prev_outs.map(&:value).inject(:+)
      return nil  unless input_value >= (output_value + fee)

      outputs.each do |type, *addrs, value|
        script = nil
        case type
        when :pubkey
          pubkey = @keystore.key(addrs[0])
          raise "Public key for #{addrs[0]} not known"  unless pubkey
          script = Bitcoin::Script.to_pubkey_script(pubkey[:key].pub)
        when :address
          if Bitcoin.valid_address?(addrs[0])
            addr = addrs[0]
          else
            addr = @keystore.key(addrs[0])[:addr] rescue nil
          end
          raise "Invalid address: #{addr}"  unless Bitcoin.valid_address?(addr)
          script = Bitcoin::Script.to_address_script(addr)
        when :multisig
          m, *addrs = addrs
          addrs.map!{|a| keystore.key(a)[:key].pub rescue raise("public key for #{a} not known")}
          script = Bitcoin::Script.to_multisig_script(m, *addrs)
        else
          raise "unknown script type: #{type}"
        end
        txout = Bitcoin::Protocol::TxOut.new(value, script.bytesize, script)
        tx.add_out(txout)
      end

      change_value = input_value - output_value - fee
      if change_value > 0
        change_addr = get_change_addr(change_policy,prev_outs.sample.get_address)
        change = Bitcoin::Protocol::TxOut.value_to_address(input_value - output_value - fee, change_addr)
        tx.add_out(change)
      end

      prev_outs.each_with_index do |prev_out, idx|
        prev_tx = prev_out.get_tx
        txin = Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash,
          prev_tx.out.index(prev_out), 0)
        tx.add_in(txin)
      end

      sigs_missing = false
      prev_outs.each_with_index do |prev_out, idx|
        prev_tx = prev_out.get_tx
        pk_script = Bitcoin::Script.new(prev_out.pk_script)
        if pk_script.is_pubkey? || pk_script.is_hash160?
          key = @keystore.key(prev_out.get_address)
          if key && key[:key] && !key[:key].priv.nil?
            sig_hash = tx.signature_hash_for_input(idx, prev_tx)
            sig = key[:key].sign(sig_hash)
            script_sig = Bitcoin::Script.to_pubkey_script_sig(sig, [key[:key].pub].pack("H*"))
          end
        elsif pk_script.is_multisig?
          sigs = []
          required_sigs = pk_script.get_signatures_required
          pk_script.get_multisig_pubkeys.each do |pub|
            break  if sigs.size == required_sigs
            key = @keystore.key(pub.unpack("H*")[0])[:key] rescue nil
            next  unless key && key.priv
            sig_hash = tx.signature_hash_for_input(idx, prev_tx)
            sig = [key.sign(sig_hash), "\x01"].join
            sigs << sig
          end
          if sigs.size == required_sigs
            script_sig = Bitcoin::Script.to_multisig_script_sig(*sigs)
          else
            puts "Need #{required_sigs} signatures, only have #{sigs.size} private keys"
            sigs_missing = true
          end
        end
        if script_sig
          tx.in[idx].script_sig_length = script_sig.bytesize
          tx.in[idx].script_sig = script_sig
          raise "Signature error"  unless tx.verify_input_signature(idx, prev_tx)
        else
          return Bitcoin::Wallet::TxDP.new([tx, *prev_outs.map(&:get_tx)])
        end
      end

      Bitcoin::Protocol::Tx.new(tx.to_payload)
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
