# encoding: ascii-8bit

module Bitcoin::Gui
  class ConnView < TreeView
    def initialize gui
      super(gui, :conn_view, [
          [GObject::TYPE_STRING, "Host"],
          [GObject::TYPE_INT, "Port"],
          [GObject::TYPE_STRING, "State"],
          [GObject::TYPE_INT, "Version", :format_version_col],
          [GObject::TYPE_INT, "Block"],
          [GObject::TYPE_INT, "Uptime", :format_uptime_col],
          [GObject::TYPE_STRING, "User Agent"]])
      @view.set_model @model
    end

    def connected data
      row = @model.append(nil)
      data.each_with_index do |pair, i|
        @model.set_value(row, i, pair[1] || "")
      end
    end

    def disconnected data
      valid, i = @model.get_iter_first
      while valid
        host = @model.get_value(i, 0).get_string
        port = @model.get_value(i, 1).get_int
        if host == data[0] && port == data[1]
          @model.remove(i)
          break
        end
        valid = @model.iter_next(i.to_ptr)
      end
    end

  end
end
