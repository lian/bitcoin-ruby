# encoding: ascii-8bit

class Bitcoin::Wallet::TxDP

  attr_accessor :id, :tx, :inputs
  def initialize tx = []
    @id = Bitcoin.int_to_base58(rand(1e14))
    @tx = tx
    @inputs = []
    return  unless tx.any?
    @tx[0].in.each_with_index do |input, i|
      prev_out_hash = input.prev_out.reverse_hth
      prev_tx = @tx[1..-1].find {|tx| tx.hash == prev_out_hash}
      raise "prev tx #{prev_out_hash} not found"  unless prev_tx
      prev_out = prev_tx.out[input.prev_out_index]
      raise "prev out ##{input.prev_out_index} not found in tx #{@tx.hash}"  unless prev_out
      out_script = Bitcoin::Script.new(prev_out.pk_script)
      out_script.get_addresses.each do |addr|
        add_sig(i, prev_out.value, addr, input.script_sig)
      end
    end
  end

  def add_sig(in_idx, value, addr, sig)
    sig = sig ? [[addr, sig.unpack("H*")[0]]] : []
    @inputs[in_idx] = [value, sig]
  end

  def sign_inputs
    @inputs.each_with_index do |txin, i|
      input = @tx[0].in[i]
      prev_out_hash = input.prev_out.reverse_hth
      prev_tx = @tx[1..-1].find {|tx| tx.hash == prev_out_hash}
      raise "prev tx #{prev_out_hash} not found"  unless prev_tx
      prev_out = prev_tx.out[input.prev_out_index]
      raise "prev out ##{input.prev_out_index} not found in tx #{@tx.hash}"  unless prev_out
      out_script = Bitcoin::Script.new(prev_out.pk_script)
      out_script.get_addresses.each do |addr|
        sig = yield(@tx[0], prev_tx, i, addr)
        if sig
          @inputs[i][1] ||= []
          @inputs[i][1] << [addr, sig]
          break
        end
      end
    end
  end

  def serialize
    lines = []
    lines << "-----BEGIN-TRANSACTION-#{@id}".ljust(80, '-')
    size = [@tx.first.to_payload.bytesize].pack("C").ljust(2, "\x00").reverse_hth
    lines << "_TXDIST_#{Bitcoin.network[:magic_head].unpack("H*")[0]}_#{@id}_#{size}"
    tx = @tx.map(&:to_payload).join.unpack("H*")[0]
    tx_str = ""; tx.split('').each_with_index{|c,i| tx_str << (i % 80 == 0 ? "\n#{c}" : c)}
    lines << tx_str.strip
    @inputs.each_with_index do |input, idx|
      lines << "_TXINPUT_#{idx.to_s.rjust(2, '0')}_#{"%.8f" % (input[0].to_f / 1e8)}"
      next  unless input[1]
      input[1].each do |sig|
        size = [sig[1]].pack("H*").bytesize
        size = [size].pack("C").ljust(2, "\x00").reverse_hth
        lines << "_SIG_#{sig[0]}_#{idx.to_s.rjust(2, '0')}_#{size}"
        sig_str = ""; sig[1].split('').each_with_index{|c,i| sig_str << (i % 80 == 0 ? "\n#{c}" : c)}
        lines << sig_str.strip
      end
    end
    lines << "-------END-TRANSACTION-#{@id}".ljust(80, '-')
    lines.join("\n")
  end

  def parse str
    str.match(/-+BEGIN-TRANSACTION-(.*?)-+$(.*?)END-TRANSACTION-#{$1}/m) do |m|
      _, id, content = *m
      txdist, *inputs = content.split(/_TXINPUT_/)
      @id = id
      @txdist = parse_txdist(txdist)
      inputs.each {|input| parse_input(input) }
    end
    self
  end

  def parse_txdist txdist
    _, magic, txdp_id, size, serialized_tx = *txdist.match(/_TXDIST_(.*?)_(.*?)_(.*?)$(.*)/m)
    raise "Wrong network magic"  unless [magic].pack("H*") == Bitcoin.network[:magic_head]
    tx = Bitcoin::P::Tx.new(nil)
    rest = [serialized_tx.gsub!("\n", '')].pack("H*")
    while rest = tx.parse_data(rest)
      @tx << tx
      break  if rest == true
      tx = Bitcoin::P::Tx.new(nil)
    end
  end

  def parse_input input
    m = input.match(/(\d+)_(\d+\.\d+)\n(.*)/m)
    _, idx, value, sigs = *m
    value = (value.sub('.','').to_i)
    sigs = parse_sigs(sigs)
    @inputs[idx.to_i] = [value, sigs]
  end

  def parse_sigs sigs
    return nil  unless sigs["_SIG_"]
    sigs = sigs.split("_SIG_").map do |s|
      if s == ""
        nil
      else
        m = s.match(/(.*?)_(\d+)_(.*?)\n(.*)/m)
        [$1, $4.gsub("\n", '').gsub('-', '')]
      end
    end.compact
  end

  def self.parse str
    new.parse str
  end
end
