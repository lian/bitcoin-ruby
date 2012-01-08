module Bitcoin::Wallet

  class Wallet

    attr_reader :keystore
    def initialize storage, keystore, selector
      @storage = storage
      @keystore = keystore
      @selector = selector
    end

    def get_txouts
      @keystore.keys.map {|k|
        @storage.get_txouts_for_address(k.addr)}.flatten
    end

    def get_balance
      values = get_txouts.select{|o| !o.get_next_in}.map(&:value)
      ([0] + values).inject(:+)
    end

    def addrs
      @keystore.keys.map{|k| k.addr}
    end

    def list
      @keystore.keys.map do |key|
        [key.addr, @storage.get_balance(Bitcoin.hash160_from_address(key.addr))]
      end
    end

    def get_new_addr
      @keystore.new_key.addr
    end

    def get_selector
      @selector.new(get_txouts)
    end

    # outputs = [<addr>, <value>]
    def tx outputs, fee = 0, change_policy = :back
      prev_outs = get_selector.select(outputs.map{|o| o[1]}.inject(:+))
      return nil  if !prev_outs

      tx = Bitcoin::Protocol::Tx.new(nil)

      input_value = prev_outs.map(&:value).inject(:+)
      output_value = outputs.map{|o|o[1]}.inject(:+)
      return nil  unless input_value >= (output_value + fee)

      outputs.each do |addr, value|
        script = Bitcoin::Script.to_address_script(addr)
        txout = Bitcoin::Protocol::TxOut.new(value, script.bytesize, script)
        tx.add_out(txout)
      end

      change_value = input_value - output_value - fee
      if change_value > 0
        change_addr = get_change_addr(change_policy,prev_outs.sample.get_address)
        pk_script = Bitcoin::Script.to_address_script(change_addr)
        change = Bitcoin::Protocol::TxOut.new(input_value - output_value - fee,
          pk_script.bytesize, pk_script)
        tx.add_out(change)
      end

      prev_outs.each_with_index do |prev_out, idx|
        prev_tx = prev_out.get_tx
        txin = Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash,
          prev_tx.out.index(prev_out), 0)
        tx.add_in(txin)
      end

      prev_outs.each_with_index do |prev_out, idx|
        prev_tx = prev_out.get_tx
        key = @keystore.key(prev_out.get_address)
        sig_hash = tx.signature_hash_for_input(idx, prev_tx)
        sig = key.sign(sig_hash)
        script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [key.pub].pack("H*"))
        tx.in[idx].script_sig_length = script_sig.bytesize
        tx.in[idx].script_sig = script_sig
        raise "Signature error"  unless tx.verify_input_signature(idx, prev_tx)
      end

      Bitcoin::Protocol::Tx.new(tx.to_payload)
    end

    protected

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
