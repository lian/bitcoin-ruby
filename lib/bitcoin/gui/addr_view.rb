module Bitcoin::Gui
  class AddrView < TreeView

    def initialize gui
      super(gui, :addr_view, [
          [GObject::TYPE_STRING, "Address", :format_address_col],
          [GObject::TYPE_STRING],
          [GObject::TYPE_STRING, "Balance", :format_value_col]])
      embed(:addr_view)
    end

    def update addrs
      @model.clear
      addrs.each do |addr, balance|
        row = @model.append(nil)
        @model.set_value(row, 0, addr[:addr])
        @model.set_value(row, 1, addr[:label] || "")
        @model.set_value(row, 2, balance.to_s)

        @gui.storage.get_txouts_for_address(addr[:addr]).each do |txout|
          tx_row = @model.append(row)
          @model.set_value(tx_row, 0, txout.get_tx.hash)
          @model.set_value(tx_row, 2, txout.value.to_s)
        end
      end
      @view.set_model @model
    end

  end
end
