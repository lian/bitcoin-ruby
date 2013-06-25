# encoding: ascii-8bit

module Bitcoin::Gui
  class TreeView

    include Helpers

    attr_accessor :model, :view

    def initialize gui, view_name, columns
      @gui = gui
      @view = @gui.builder.get_object(view_name.to_s)
      @model = Gtk::TreeStore.new(columns.map{|c| c[0] })
      @view.set_model @model

      columns.each_with_index do |cdef, i|
        type, label, cb = *cdef
        next  unless label
        case type
        when GObject::TYPE_BOOLEAN
          renderer = Gtk::CellRendererToggle.new
          col = tree_view_col(renderer, label, "active", i) do |*args|
            method(cb).call(@model, i, args[1], args[3])  if cb
          end
        when GObject::TYPE_STRING, GObject::TYPE_INT
          renderer = Gtk::CellRendererText.new
          col = tree_view_col(renderer, label, "text", i) do |*args|
            method(cb).call(@model, i, args[1], args[3])  if cb
          end
        end
        @view.append_column(col)
      end
    end

    def embed name
      parent = @gui.builder.get_object(name.to_s).parent
      parent.remove(parent.get_child)
      parent.add(@view)
    end

    def tree_view_col renderer, title, key, val, &block
      col = Gtk::TreeViewColumn.new
      col.pack_start renderer, true
      col.add_attribute renderer, key, val
      col.set_title title
      col.set_cell_data_func(renderer, block, nil, nil)
      col
    end

    def format_address_col model, i, renderer, iter
      address = model.get_value(iter, i).get_string
      label = model.get_value(iter, i+1).get_string
      renderer.text = format_address(address, label)
    end

    def format_value_col model, i, renderer, iter
      val = model.get_value(iter, i).get_string.to_i
      renderer.text = format_value(val)
      if val > 0
        renderer.foreground = "darkgreen"
      elsif val < 0
        renderer.foreground = "red"
      else
        renderer.foreground = "black"
      end
    end

    def format_version_col model, i, renderer, iter
      ver = model.get_value(iter, i).get_int.to_s
      renderer.text = format_version(ver)
    end

    def format_uptime_col model, i, renderer, iter
      started = model.get_value(iter, i).get_int
      renderer.text = format_uptime(started)
    end

    def format_bool_col model, i, renderer, iter
      active = model.get_value(iter, i).get_boolean
      renderer.set_active active
    end

  end
end
