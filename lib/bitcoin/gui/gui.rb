require_relative "em_gtk.rb"

module Bitcoin::Gui

  class Gui
    attr_reader :builder
    attr_accessor :node, :conn_view, :conn_store
    def initialize storage, wallet_file = nil
      @storage = storage
      @node = nil
      @builder = Gtk::Builder.new
      @builder.add_from_file(File.join(File.dirname(__FILE__), "gui.builder"))
      @builder.connect_signals {|handler| method(handler)}
      @window = @builder.get_object("main_window")
      setup_addr_view
      setup_conn_view
      open_wallet(wallet_file)  if wallet_file
      @window.show_all
    end

    # VIEWS

    def setup_addr_view
      @addr_view = @builder.get_object("address_view")
      @addr_view.selection.mode = :multiple

      renderer = Gtk::CellRendererText.new
      col = Gtk::TreeViewColumn.new("Address", renderer, :text => 0)
      @addr_view.append_column(col)
      col.set_cell_data_func(renderer) {|*a| format_address(*a) }

      renderer = Gtk::CellRendererText.new
      col = Gtk::TreeViewColumn.new("Balance", renderer, :text => 1)
      col.set_cell_data_func(renderer) {|*a| format_value(*a) }
      @addr_view.append_column(col)

      @addr_store = Gtk::TreeStore.new(String, String, Fixnum)
    end

    def setup_conn_view
      @conn_view = @builder.get_object("connections_view")
      renderer = Gtk::CellRendererText.new
      %w[Host Port State Version Block Uptime UserAgent].each_with_index do |c, i|
        @conn_view.append_column(Gtk::TreeViewColumn.new(c, renderer, :text => i))
      end
      @conn_view.columns[3].set_cell_data_func(renderer) {|*a| format_version(*a) }
      @conn_view.columns[5].set_cell_data_func(renderer) {|*a| format_uptime(*a) }
      @conn_store = Gtk::TreeStore.new(String, Fixnum, String, Fixnum, Fixnum, Fixnum, String)
    end

    # STORES

    def update_addr_store
      return  unless @wallet
      @addr_store.clear
      @wallet.list.each do |addr, balance|
        addr_row = @addr_store.append(nil)
        addr_row[0] = addr[:addr]
        addr_row[1] = addr[:label]
        addr_row[2] = balance
        @wallet.storage.get_txouts_for_address(addr[:addr]).each do |txout|
          row = @addr_store.append(addr_row)
          row[0] = txout.get_tx.hash
          row[2] = txout.value
        end
      end
      @addr_view.model = @addr_store
      wallet_text = "wallet: #{@wallet.keystore.config[:file]} | " +
        "addresses: #{@wallet.addrs.size} | " +
        "balance: #{"%.8f" % (@wallet.get_balance / 1e8)}"
      status_wallet.push 0, wallet_text
    end

    # CALLBACKS

    def on_new_addr
      new_addr_entry_label.text = ""
      new_addr_dialog.show
    end

    def on_new_addr_apply
      @wallet.keystore.new_key(new_addr_entry_label.text)
      update_addr_store
      new_addr_dialog.hide
    end

    def on_new_addr_cancel
      @key = nil
      new_addr_dialog.hide
    end

    def on_new_wallet
      wallet_dialog(:save, "File to save new wallet") do |file|
        open_wallet(file)
      end
    end

    def on_open_wallet
      wallet_dialog(:open, "Select wallet file to open") do |file|
        open_wallet(file)
      end
    end

    def on_exit
      Gtk.main_quit
      EM.stop
    end

    # HELPERS

    def open_wallet(file)
      keystore = Bitcoin::Wallet::SimpleKeyStore.new(:file => file)
      @wallet = Bitcoin::Wallet::Wallet.new(@storage, keystore, Bitcoin::Wallet::SimpleCoinSelector)
      update_addr_store
    end

    def wallet_dialog action, title = nil
      dialog = Gtk::FileChooserDialog.new(title: title,
        parent: @window, action: action, buttons: [
          [ Gtk::Stock::CANCEL, :cancel],
          [ Gtk::Stock::const_get(action.to_s.upcase), :accept],
        ]
        )

      filter = Gtk::FileFilter.new
      filter.name = "Wallet Files"
      filter.add_pattern("*.json")
      dialog.add_filter filter

      filter = Gtk::FileFilter.new
      filter.name = "All Files"
      filter.add_pattern("*")
      dialog.add_filter filter

      preview = Gtk::Label.new
      dialog.preview_widget = preview
      dialog.signal_connect("update-preview") do
        begin
          file = dialog.preview_filename
          next  unless file && File.file?(file)
          keystore = Bitcoin::Wallet::SimpleKeyStore.new(:file => file)
          wallet = Bitcoin::Wallet::Wallet.new(@storage, keystore, Bitcoin::Wallet::SimpleCoinSelector)
          preview.text = "Keys: #{wallet.addrs.size}\nBalance:\n%.8f" % (wallet.get_balance / 1e8)
        rescue
          preview.text = "Not a wallet file"
        end
      end

      dialog.run do |res|
        yield(dialog.filename)  if res == Gtk::ResponseType::ACCEPT
        dialog.destroy
      end
    end

    def format_value col, renderer, model, iter
      val = iter[2].to_i
      renderer.text = "%.8f" % (val / 1e8)
      if val > 0
        renderer.foreground = "darkgreen"
      elsif val < 0
        renderer.foreground = "red"
      else
        renderer.foreground = "black"
      end
    end

    def format_address col, renderer, model, iter
      renderer.text = "#{iter[1]} (#{iter[0]})"
    end

    def format_version col, renderer, model, iter
      renderer.text = iter[3].to_s # TODO
    end

    def format_uptime col, renderer, model, iter
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
