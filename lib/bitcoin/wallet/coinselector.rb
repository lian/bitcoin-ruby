module Bitcoin::Wallet

  class SimpleCoinSelector

    def initialize txouts
      @txouts = txouts
    end

    def select(value)
      txouts = []
      @txouts.each do |txout|
        begin
          next  if txout.get_next_in
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
