module Bitcoin
  class BlockBuilder

    def initialize
      @block = Bitcoin::P::Block.new(nil)
    end

    def version v
      @version = v
    end

    def prev_block hash
      @prev_block = hash
    end

    def tx &block
      c = TxBuilder.new
      c.instance_eval &block
      @block.tx << c.tx
    end

    def block target
      @block.ver = @version || 1
      @block.prev_block = [@prev_block].pack("H*").reverse
      @block.mrkl_root = @mrkl_root
      @block.time = Time.now.to_i
      @block.nonce = 0
      @block.mrkl_root = [Bitcoin.hash_mrkl_tree(@block.tx.map {|t|
            t.hash }).last].pack("H*")
      find_hash(target)
      Bitcoin::P::Block.new(@block.to_payload)
    end

    def find_hash target
      @block.bits = Bitcoin.encode_compact_bits(target)
      t = Time.now
      @block.recalc_block_hash
      until @block.hash < target
        @block.nonce += 1
        @block.recalc_block_hash
        if @block.nonce == 100000
          if t
            tt = 1 / ((Time.now - t) / 100000) / 1000
            print "\r%.2f khash/s" % tt
          end
          t = Time.now
          @block.time = Time.now.to_i
          @block.nonce = 0
          $stdout.flush
        end
      end
    end

  end

  class TxBuilder

    def initialize
      @tx = Bitcoin::P::Tx.new(nil)
      @tx.ver, @tx.lock_time = 1, 0
      @ins, @outs = [], []
    end

    def version n
      @tx.ver = n
    end

    def lock_time n
      @tx.lock_time = n
    end

    def input &block
      c = TxInBuilder.new
      c.instance_eval &block
      @ins << c
    end

    def output &block
      c = TxOutBuilder.new
      c.instance_eval &block
      @outs << c
    end

    def tx
      @ins.each {|i| @tx.add_in(i.txin) }
      @outs.each {|o| @tx.add_out(o.txout) }
      @ins.each_with_index do |inc, i|
        if @tx.in[i].coinbase?
          script_sig = [inc.coinbase_data].pack("H*")
          @tx.in[i].script_sig_length = script_sig.bytesize
          @tx.in[i].script_sig = script_sig
          next
        end
        prev_tx = inc.instance_variable_get(:@prev_out)
        sig_hash = @tx.signature_hash_for_input(i, prev_tx)
        sig = inc.key.sign(sig_hash)
        script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [inc.key.pub].pack("H*"))
        @tx.in[i].script_sig_length = script_sig.bytesize
        @tx.in[i].script_sig = script_sig
        raise "Signature error"  unless @tx.verify_input_signature(i, prev_tx)
      end
      Bitcoin::P::Tx.new(@tx.to_payload)
    end
  end

  class TxInBuilder
    attr_reader :key, :coinbase_data

    def initialize
      @txin = Bitcoin::P::TxIn.new
    end

    def prev_out tx
      @prev_out = tx
    end

    def prev_out_index i
      @prev_out_index = i
    end

    def sequence s
      @sequence = s
    end

    def signature_key key
      @key = key
    end

    def coinbase data = nil
      @coinbase_data = data || OpenSSL::Random.random_bytes(32)
      @prev_out = nil
      @prev_out_index = 4294967295
    end

    def txin
      @txin.prev_out = (@prev_out ? [@prev_out.hash].pack("H*").reverse : "\x00"*32)
      @txin.prev_out_index = @prev_out_index
      @txin.sequence = @sequence || "\xff\xff\xff\xff"
      @txin
    end
  end

  class ScriptBuilder
    attr_reader :script

    def initialize
      @type = nil
      @script = nil
    end

    def type type
      @type = type.to_sym
    end

    def recipient data
      @script = Bitcoin::Script.send("to_#{@type}_script", data)
    end
  end

  class TxOutBuilder
    attr_reader :txout

    def initialize
      @txout = Bitcoin::P::TxOut.new
    end

    def value value
      @txout.value = value
    end

    def script &block
      c = ScriptBuilder.new
      c.instance_eval &block
      @txout.pk_script_length = c.script.bytesize
      @txout.pk_script = c.script
    end

  end

  module Builder

    def blk(target = "00".ljust(32, 'f'), &block)
      c = BlockBuilder.new
      c.instance_eval &block
      c.block(target)
    end

    def tx &block
      c = TxBuilder.new
      c.instance_eval &block
      c.tx
    end

  end
end
