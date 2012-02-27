class Bitcoin::Wallet::TxDP

  attr_accessor :id, :tx, :inputs
  def initialize
    @tx = []
    @inputs = []
  end

  def serialize
    lines = []
    lines << "-----BEGIN-TRANSACTION-#{@id}".ljust(80, '-')
    lines << "_TXDIST_#{Bitcoin.network[:magic_head].unpack("H*")[0]}_#{@id}_00a0" #TODO size
    tx = @tx.map(&:to_payload).join.unpack("H*")[0]
    tx_str = ""; tx.split('').each_with_index{|c,i| tx_str << (i % 80 == 0 ? "\n#{c}" : c)}
    lines << tx_str.strip
    @inputs.each_with_index do |input, idx|
      lines << "_TXINPUT_#{idx.to_s.rjust(2, '0')}_#{"%.8f" % (input[0].to_f / 1e8)}"
      input[1].each do |sig|
        lines << "_SIG_#{sig[0]}_#{idx.to_s.rjust(2, '0')}_008c" # TODO size
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
    m = input.match(/(\d+)_(\d+).(\d+)\n(.*)/m)
    _, idx, maj, min, sigs = *m
    value = ("#{maj}.#{min}".to_f * 1e8).to_i
    sigs = parse_sigs(sigs)
    @inputs[idx.to_i] = [value, sigs]
  end

  def parse_sigs sigs
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
