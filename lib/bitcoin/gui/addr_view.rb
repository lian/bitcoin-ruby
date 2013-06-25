# encoding: ascii-8bit

module Bitcoin::Gui
  class AddrView < TreeView

    def initialize gui
      super(gui, :addr_view, [
          [GObject::TYPE_STRING, "Address", :format_address_col],
          [GObject::TYPE_STRING],
          [GObject::TYPE_STRING, "Balance", :format_value_col],
          [GObject::TYPE_BOOLEAN, "Mine?"]])
    end

    def update addrs
      EM.defer do
        @model.clear
        addrs.each do |addr|
          row = @model.append(nil)
          @model.set_value(row, 0, addr[:addr])
          @model.set_value(row, 1, addr[:label] || "")
          @model.set_value(row, 3, !!addr[:mine])
          balance = 0
          unconfirmed = @gui.check_unconfirmed.active
          @gui.storage.get_txouts_for_address(addr[:addr]).each do |txout|
            next  if !unconfirmed && !txout.get_tx.get_block
            tx_row = @model.append(row)
            @model.set_value(tx_row, 0, txout.get_tx.hash)
            @model.set_value(tx_row, 2, txout.value.to_s)
            balance += txout.value
            if txin = txout.get_next_in
              tx_row = @model.append(row)
              @model.set_value(tx_row, 0, txin.get_tx.hash)
              @model.set_value(tx_row, 2, (0 - txout.value).to_s)
              balance -= txout.value
            end
          end
          @model.set_value(row, 2, balance.to_s)
        end
        @view.set_model @model
      end
    end

  end
end
