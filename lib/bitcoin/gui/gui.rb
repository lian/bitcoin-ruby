require_relative "em_gtk.rb"
require_relative "helpers.rb"
require_relative "tree_view.rb"
require_relative "addr_view.rb"
require_relative "tx_view.rb"
require_relative "conn_view.rb"

Gtk.init

module Bitcoin::Gui

  class Gui

    include Helpers

    attr_reader :builder, :wallet, :storage
    attr_accessor :node, :addr_view, :conn_view

    def initialize storage, wallet_file = nil
      @storage = storage
      @node = nil
      build
      @addr_view = AddrView.new(self)
      @tx_view = TxView.new(self, :tx_view)
      @conn_view = ConnView.new(self)
      open_wallet(wallet_file)  if wallet_file
      main_window.show_all
      # notebook.next_page
      statusicon.tooltip_text = "Bitcoin-Ruby GUI"
      GObject.signal_connect(statusicon, "activate") do
        main_window.visible ? main_window.hide : main_window.show
      end
      GObject.signal_connect(statusicon, "popup-menu") do
        popup_menu.popup_for_device(nil, nil, nil, ->(*a) {}, nil, nil, 0, 0)
      end
    end

    def log
      @log ||= Bitcoin::Logger.create(:gui)
    end

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
        "<Control>v" => :edit_paste,
        "<Control>p" => :edit_preferences,
        "<Control>h" => :help_about,
      }.each do |binding, action|
        send("menu_#{action}").add_accelerator("activate", accelgroup1,
          *Gtk.accelerator_parse(binding), 0)
      end
    end

    def update_wallet_views
      return  unless @wallet
      @addr_view.update(@wallet.list)
      @tx_view.update(@wallet.get_txouts(true))
      wallet_text = "wallet: #{@wallet.keystore.config[:file]} | " +
        "addresses: #{@wallet.addrs.size} | " +
        "balance: #{"%.8f" % (@wallet.get_balance / 1e8)}"
      status_wallet.push 0, wallet_text
    end

    def on_preferences
      dialog(:preferences, :setup => ->(d) {
          config = Bitcoin::Config.load({}, :wallet)
          model = preferences_box_network.get_model
          row = model.append
          model.set_value(row, 0, "foo")
          preferences_box_network.set_model model
          # preferences_entry_network.text = config[:network]
        }) do |*a|
        p a
      end
    end

    def on_copy_addr
      addrs = []
      valid, i = @addr_view.model.get_iter_first
      while valid
        if @addr_view.view.selection.iter_is_selected(i)
          a = @addr_view.model.get_value(i, 0).get_string
          addrs << a
        end
        valid = @addr_view.model.iter_next(i.to_ptr)
      end

      return  unless addrs.any?
      text = addrs.join(", ")
      c = Gtk::Clipboard.get(Gdk::Atom.intern("PRIMARY", false))
      c.set_text text, text.size
      c = Gtk::Clipboard.get(Gdk::Atom.intern("CLIPBOARD", false))
      c.set_text text, text.size
    end

    def on_new_addr
      dialog(:new_addr, setup: ->(d) {
          new_addr_check_addr.active = false
          new_addr_check_pubkey.active = false
          new_addr_check_mine.active = true
          [:label, :addr, :pubkey].each {|n| send("new_addr_entry_#{n}").text = "" }
          [:addr, :pubkey].each {|n| send("new_addr_entry_#{n}").hide }
          GObject.signal_connect(new_addr_check_addr, "toggled") do
            new_addr_check_addr.active ? new_addr_entry_addr.show :
              new_addr_entry_addr.hide
          end
          GObject.signal_connect(new_addr_check_pubkey, "toggled") do
            new_addr_check_pubkey.active ? new_addr_entry_pubkey.show :
              new_addr_entry_pubkey.hide
          end
        }) do |*a|
        begin
          label = new_addr_entry_label.text
          set_address = new_addr_check_addr.active
          set_pubkey = new_addr_check_pubkey.active
          is_mine = new_addr_check_mine.active
          key = {:label => label}
          if set_address
            addr = new_addr_entry_addr.text
            raise "Address #{addr} invalid"  unless Bitcoin.valid_address?(addr)
            key[:addr] = addr
          end
          if set_pubkey
            k = Bitcoin::Key.new(nil, new_addr_entry_pubkey.text)
            key[:key] = k
            key[:addr] = k.addr
          end
          if !set_addr && !set_pubkey
            key[:key] = Bitcoin::Key.generate
            key[:addr] = key[:key].addr
          end
          key[:mine] = is_mine
          @wallet.add_key(key)
          update_wallet_views
        rescue
          message(:error, "Error adding key", $!.message, [:ok]) do
            new_addr_dialog.show
          end
        end
        update_addr_store
      end
    end

    def on_new_tx
      dialog(:new_tx, :setup => ->(d) {
          new_tx_entry_address.text = ""
          new_tx_entry_amount.text = ""
          model = Gtk::ListStore.new([GObject::TYPE_STRING, GObject::TYPE_STRING])
          @wallet.keystore.keys.each do |key|
            row = model.append
            model.set_value(row, 0, "#{key[:addr]}\n#{key[:label]}")
            model.set_value(row, 1, key[:addr])
          end
          renderer = Gtk::CellRendererText.new
          comp = Gtk::EntryCompletion.new_with_area(area)
          comp.text_column = 0
          comp.minimum_key_length = 1
          comp.set_match_func(->(comp, text, iter, _) {
              label = comp.get_model.value(iter, 0).get_string
              addr = comp.get_model.value(iter, 1).get_string
              !!(label =~ /#{text}/ || addr =~ /#{text}/)
            }, nil, nil)
          comp.set_model model
          new_tx_entry_address.set_completion comp
          GObject.signal_connect(comp, "match-selected") do |comp, _, iter, _|
            addr = comp.get_model.get_value(iter, 1).get_string
            new_tx_entry_address.text = addr
            true
          end
        }) do |dialog|

        address = new_tx_entry_address.text
        amount = new_tx_entry_amount.text
        unless Bitcoin.valid_address?(address)
          message(:error, "Invalid Address",
            "Address #{address} is not a valid bitcoin address.", [:ok]) do
            new_tx_dialog.show
          end
          next
        end
        unless amount =~ /[0-9]*\.[0-9]*/
          message(:error, "Invalid Amount",
            "Amount #{amount} can not be parsed. Please use \"0.0\" form.", [:ok]) do
            new_tx_dialog.show
          end
          next
        end
        value = (amount.to_f * 1e8).to_i
        unless value <= @wallet.get_balance
          message(:error, "Insufficient Balance",
            "Balance #{@wallet.get_balance} is not sufficient to spend #{value}.", [:ok]) do
            dialog.show
          end
          next
        end
        message(:question, "Really send transaction?",
          "Do you really want to send #{format_value value} to #{address}?", [:no, :yes]) do
          tx = @wallet.tx([[:address, *[address], value]], 0.00)
          puts tx.to_json
          if @node.request(:relay_tx, tx)
            p 'hoho'
          end
        end
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

    def open_wallet(file)
      keystore = Bitcoin::Wallet::SimpleKeyStore.new(:file => file)
      @wallet = Bitcoin::Wallet::Wallet.new(@storage, keystore,
        Bitcoin::Wallet::SimpleCoinSelector)
      @wallet.on_tx do |type, tx|
        puts "#{type} transaction: #{tx.hash}"
        update_wallet_views
        value = tx.out.select {|out| (@wallet.addrs & out.get_addresses).any? }
          .map(&:value).inject(:+)
        title = "#{type.to_s.capitalize} transaction"
        message = "#{tx.hash}\nValue: #{format_value(value)}"
        Notify.notify title, message
      end
      update_wallet_views
    rescue
      message(:error, "Error loading wallet", $!.message, [:ok])
      p $!
      puts *$@
    end

  end
end
