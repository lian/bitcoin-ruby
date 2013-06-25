# encoding: ascii-8bit

module Bitcoin::Gui
  class TxView < TreeView

    def initialize gui, replace = nil
      super(gui, :tx_view, [
          [GObject::TYPE_STRING, "Type"],
          [GObject::TYPE_STRING, "Hash"],
          [GObject::TYPE_STRING, "Value", :format_value_col],
          [GObject::TYPE_INT, "Confirmations"],
          [GObject::TYPE_STRING, "Direction"],
        ])
      GObject.signal_connect(@view, "row-activated") do |view, path, column|
        res, iter = @model.get_iter(path)
        next  unless res
        tx_hash = @model.get_value(iter, 1).get_string
        @gui.display_tx(tx_hash)
      end
    end

    def update txouts
      EM.defer do
        @model.clear
        txouts.each do |txout|
          row = @model.append(nil)
          @model.set_value(row, 0, txout.type.to_s)
          @model.set_value(row, 1, txout.get_tx.hash)
          @model.set_value(row, 2, txout.value.to_s)
          @model.set_value(row, 3, txout.get_tx.confirmations)
          @model.set_value(row, 4, "incoming")
          if txin = txout.get_next_in
            row = @model.append(nil)
            @model.set_value(row, 0, txout.type.to_s)
            @model.set_value(row, 1, txin.get_tx.hash)
            @model.set_value(row, 2, (0 - txout.value).to_s)
            @model.set_value(row, 3, txin.get_tx.confirmations)
            @model.set_value(row, 4, "outgoing")
          end
        end
        @view.set_model @model
      end
    end
  end

  class TxInView < TreeView
    def initialize gui, replace = nil
      super(gui, [
          [GObject::TYPE_STRING, "Type"],
          [GObject::TYPE_STRING, "From"],
          [GObject::TYPE_STRING, "Value", :format_value_col]
        ])
      old = @gui.builder.get_object("tx_view")
    end

    def update txins
      @model.clear
      txins.each do |txin|
        txout = txin.get_prev_out
        row = @model.append(nil)
        @model.set_value(row, 0, txout.type.to_s)
        @model.set_value(row, 1, txout.get_addresses.join(", "))
        @model.set_value(row, 2, txout.value.to_s)
      end
      @view.set_model @model
    end
  end

end
