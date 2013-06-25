# encoding: ascii-8bit

module Bitcoin::Gui::Helpers

  def display_tx tx_hash
    tx = @storage.get_tx(tx_hash)
    dialog(:tx, setup: ->(d) {
        tx_label_hash.text = tx.hash
        tx_label_value.text = format_value(tx.out.map(&:value).inject(:+))
        tx_label_confirmations.text = tx.confirmations.to_s
        txin_view = Bitcoin::Gui::TxInView.new(self, :tx_txin_view)
#        txin_view.update(tx.in)
      })
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
    @dialog_cb_ids ||= {}
    ids = @dialog_cb_ids[name] || []
    dialog = send("#{name}_dialog")
    send("add_#{opts[:filters]}_filters", dialog)  if opts[:filters]
    opts[:setup].call(dialog)  if opts[:setup]
    while id = ids.shift
      GObject.signal_handler_disconnect(dialog, id)
    end
    ids << GObject.signal_connect(dialog, "response") do |dialog, response, *data|
      yield(dialog, *data)  if response > 0
      dialog.hide
    end
    if dialog.is_a?(Gtk::FileChooserDialog)
      ids << GObject.signal_connect(dialog, "file-activated") do |dialog, *data|
        yield(dialog, *data)
        dialog.hide
      end
    end
    (opts[:callbacks] || {}).each do |name, block|
      ids << GObject.signal_connect(dialog, name) {|*a| block.call(*a) }
    end
    dialog.show
    @dialog_cb_ids[name] = ids
  rescue
    p $!
    puts *$@
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
      yield(dialog)  if block_given?
      dialog.show_all
      dialog.hide
    end
  rescue
    p $!
  end

  def method_missing name, *args
    @builder.get_object(name.to_s) rescue super(name, *args)
  end

  def format_value val
    "%.8f" % (val / 1e8)
  end

  def format_address address, label = nil
    "#{label} (#{address})"
  end

  def format_version ver
    ver.insert(-3, '.')  if ver.size > 2
    ver.insert(-6, '.')  if ver.size > 5
    ver.insert(0, "0.")  if ver.size <= 7
    ver
  end

  def format_uptime started
    uptime = Time.now.to_i - started
    mm, ss = uptime.divmod(60)       #=> [4515, 21]
    hh, mm = mm.divmod(60)           #=> [75, 15]
    dd, hh = hh.divmod(24)           #=> [3, 3]
    "%02d:%02d:%02d:%02d" % [dd, hh, mm, ss]
  end

end
