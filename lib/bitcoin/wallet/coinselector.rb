# encoding: ascii-8bit

module Bitcoin::Wallet

  # select unspent txouts to be used by the Wallet when creating a new transaction
  class SimpleCoinSelector

    # create coinselector with given +txouts+
    def initialize txouts
      @txouts = txouts
    end

    # select txouts needed to spend +value+ btc (base units)
    def select(value)
      txouts = []
      @txouts.each do |txout|
        begin
          next  if txout.get_next_in
          next  if Bitcoin.namecoin? && txout.type.to_s =~ /^name_/
          next  unless txout.get_address
          next  unless txout.get_tx.get_block
          txouts << txout
          return txouts  if txouts.map(&:value).inject(:+) >= value
        rescue
          p $!
        end
      end
      nil
    end

  end

end
