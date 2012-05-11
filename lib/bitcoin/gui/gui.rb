require_relative "em_gtk.rb"

Gtk.init

module Bitcoin::Gui

  class Gui
    attr_reader :builder
    attr_accessor :node, :conn_view, :conn_store, :addr_store
    def initialize storage, wallet_file = nil
      @storage = storage
      @node = nil
      build
      setup_addr_view
      setup_conn_view
      open_wallet(wallet_file)  if wallet_file
      main_window.show_all
    end

    # VIEWS

    def build
      @builder = Gtk::Builder.new
      @builder.add_from_file(File.join(File.dirname(__FILE__), "gui.builder"))
      @builder.connect_signals_full(->(builder, widget, signal, handler, _, _, gui) do
          GObject.signal_connect(widget, signal) { gui.send(handler) }
        end, self)

      {
        "<Control>n" => :file_new,
        "<Control>o" => :file_open,
        "<Control>q" => :file_quit,
        "<Control>c" => :edit_copy,
        "<Control>p" => :edit_paste,
        "<Control>h" => :help_about,
      }.each do |binding, action|
        send("menu_#{action}").add_accelerator("activate", accelgroup1,
          *Gtk.accelerator_parse(binding), 0)
      end
    end

    def setup_addr_view
      @addr_store = Gtk::TreeStore.new [GObject::TYPE_STRING, GObject::TYPE_STRING, GObject::TYPE_INT]
      @addr_view = Gtk::TreeView.new_with_model(@addr_store)

      renderer = Gtk::CellRendererText.new
      col = tree_view_col(renderer, "Address", "text", 0) {|*a| format_address(*a) }
      @addr_view.append_column(col)
      renderer = Gtk::CellRendererText.new
      col = tree_view_col(renderer, "Balance", "text", 1) {|*a| format_value(*a) }
      @addr_view.append_column(col)

      p = @builder.get_object("address_view").parent
      p.remove(p.get_child)

      p.add(@addr_view)
    end

    def setup_conn_view
      @conn_store = Gtk::TreeStore.new [GObject::TYPE_STRING, GObject::TYPE_INT,
        GObject::TYPE_STRING, GObject::TYPE_INT, GObject::TYPE_INT,
        GObject::TYPE_INT, GObject::TYPE_STRING]
      @conn_view = Gtk::TreeView.new_with_model(@conn_store)


      %w[Host Port State Version Block Uptime UserAgent].each_with_index do |c, i|
        renderer = Gtk::CellRendererText.new
        case c
        when "Version"
          col = tree_view_col(renderer, c, "text", i) {|*a| format_version(*a)}
        else
          col = tree_view_col(renderer, c, "text", i)
        end
        @conn_view.append_column(col)
      end
      p = @builder.get_object("connections_view").parent
      p.remove(p.get_child)
      p.add(@conn_view)
      @conn_view.show_all
    end

    # STORES

    def update_addr_store
      return  unless @wallet
      @addr_store.clear
      @wallet.list.each do |addr, balance|
        row = @addr_store.append(nil)
        @addr_store.set_value(row, 0, addr[:addr])
        @addr_store.set_value(row, 1, addr[:label] || "")
        @addr_store.set_value(row, 2, balance)
      end
      @addr_view.set_model @addr_store
      wallet_text = "wallet: #{@wallet.keystore.config[:file]} | " +
        "addresses: #{@wallet.addrs.size} | " +
        "balance: #{"%.8f" % (@wallet.get_balance / 1e8)}"
      status_wallet.push 0, wallet_text
    end

    # CALLBACKS

    def on_copy_addr
      addrs = []
      valid, i = @addr_store.get_iter_first
      while valid
        if @addr_view.selection.iter_is_selected(i)
          a = @addr_store.get_value(i, 0).get_string
          addrs << a
        end
        valid = @addr_store.iter_next(i.to_ptr)
      end

      return  unless addrs.any?
      text = addrs.join(", ")
      c = Gtk::Clipboard.get(Gdk::Atom.intern("PRIMARY", false))
      c.set_text text, text.size
      c = Gtk::Clipboard.get(Gdk::Atom.intern("CLIPBOARD", false))
      c.set_text text, text.size
    end

    def on_new_addr
      dialog(:new_addr) do |*a|
        begin
          label = new_addr_entry_label.text
          @wallet.keystore.new_key(label)
        rescue
          message(:error, "Error adding key", $!.message, [:ok])
        end
        update_addr_store
      end
    end

    def on_new_wallet
      dialog(:wallet_save, :filters => :wallet, :callbacks => {
          "update-preview" => method(:wallet_preview)}) do
        file = wallet_save_dialog.filename.read_string
        open_wallet(file)  unless File.file?(file)
      end
    end

    def on_open_wallet
      dialog(:wallet_open, :filters => :wallet, :callbacks => {
          "update-preview" => method(:wallet_preview)}) do
        open_wallet(wallet_open_dialog.filename.read_string)
      end
    end

    def on_about
      dialog(:about)
    end

    def on_exit
      puts "bye"
      Gtk.main_quit
      EM.stop
    end

    # HELPERS

    def open_wallet(file)
      keystore = Bitcoin::Wallet::SimpleKeyStore.new(:file => file)
      @wallet = Bitcoin::Wallet::Wallet.new(@storage, keystore,
        Bitcoin::Wallet::SimpleCoinSelector)
      update_addr_store
    rescue
      message(:error, "Error loading wallet", $!.message, [:ok])
    end

    def wallet_preview(dialog, *args)
      filename = dialog.preview_filename
      file = filename.read_string rescue nil
      if file && File.file?(file)
        keystore = Bitcoin::Wallet::SimpleKeyStore.new(:file => file)
        wallet = Bitcoin::Wallet::Wallet.new(@storage, keystore,
          Bitcoin::Wallet::SimpleCoinSelector)
        preview = Gtk::Label.new "Keys: #{wallet.addrs.size}\n" +
          "Balance:\n%.8f" % (wallet.get_balance / 1e8)
      end
      dialog.preview_widget = preview
    end

    def add_wallet_filters dialog
      filter = Gtk::FileFilter.new
      filter.name = "Wallet Files"
      filter.add_pattern("*.json")
      dialog.add_filter filter

      filter = Gtk::FileFilter.new
      filter.name = "All Files"
      filter.add_pattern("*")
      dialog.add_filter filter
    end

    def dialog name, opts = {}
      @dialogs ||= {}
      unless @dialogs[name]
        dialog = send("#{name}_dialog")
        send("add_#{opts[:filters]}_filters", dialog)  if opts[:filters]
        opts[:setup].call(dialog)  if opts[:setup]
        GObject.signal_connect(dialog, "response") do |dialog, response, *data|
          yield(dialog, *data)  if response > 0
          dialog.hide
        end
        if dialog.is_a?(Gtk::FileChooserDialog)
          GObject.signal_connect(dialog, "file-activated") do |dialog, *data|
            yield(dialog, *data)
            dialog.hide
          end
        end
        (opts[:callbacks] || {}).each do |name, block|
          GObject.signal_connect(dialog, name) {|*a| block.call(*a) }
        end
        @dialogs[name] = dialog
      end
      @dialogs[name].show
    end

    def tree_view_col renderer, title, key, val, &block
      col = Gtk::TreeViewColumn.new
      col.pack_start renderer, true
      col.add_attribute renderer, key, val
      col.set_title title
      col.set_cell_data_func(renderer, block, nil, nil)
      col
    end

    def message(type, title, text, buttons)
      dialog(:message, :setup => ->(dialog){
          dialog.message_type = Gtk::MessageType.find(type.to_sym)
          dialog.text = title
          dialog.secondary_text = text
          [:yes, :no, :ok].each do |n|
            b = send("message_dialog_button_#{n}")
            buttons.include?(n) ? b.show : b.hide
          end
        }) do |dialog|
        yield(dialog)
      end
    end

    def format_value col, renderer, model, iter, data
      val = @addr_store.get_value(iter, 2).get_int
      renderer.text = "%.8f" % (val / 1e8)
      if val > 0
        renderer.foreground = "darkgreen"
      elsif val < 0
        renderer.foreground = "red"
      else
        renderer.foreground = "black"
      end
    end

    def format_address col, renderer, model, iter, data
      address = @addr_store.get_value(iter, 0).get_string
      label = @addr_store.get_value(iter, 1).get_string
      renderer.text = "#{label} (#{address})"
    end

    def format_version col, renderer, model, iter, data
      version = @conn_store.get_value(iter, 3).get_int.to_s
      version.insert(-3, '.')  if version.size > 2
      version.insert(-6, '.')  if version.size > 5
      version.insert(0, "0.")  if version.size <= 7
      renderer.text = version.to_s # TODO
    end

    def format_uptime col, renderer, model, iter, data
      uptime = Time.now.to_i - iter[5]
      mm, ss = uptime.divmod(60)       #=> [4515, 21]
      hh, mm = mm.divmod(60)           #=> [75, 15]
      dd, hh = hh.divmod(24)           #=> [3, 3]
      renderer.text = "%02d:%02d:%02d:%02d" % [dd, hh, mm, ss]
    end

    def method_missing name, *args
      @builder.get_object(name.to_s) rescue super(name, *args)
    end

  end
end
