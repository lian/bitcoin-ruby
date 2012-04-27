module Bitcoin::Gui

  class Bitcoin::Network::CommandClient
    def gui &block
      EM.next_tick do
        @args[0].instance_eval &block
      end
    end
  end

  class Connection

    def initialize host, port, gui
      @gui = gui
      client = Bitcoin::Network::CommandClient.connect(host, port, gui) do

        on_connected do
          request :info
          request :monitor, "block", "connection"
        end

        on_info do |info|
          text = "connections: #{info['connections']} | " +
            "addrs: #{info['addrs']} | uptime: #{info['uptime']}"
          gui { status_network.push 0, text }
          EM::defer { sleep(1) && request(:info) }
        end

        on_block do |block, depth|
          gui { status_store.push 0, "Blocks: #{depth}" }
        end

        on_connection do |state, data|
          if state == "connected"
            row = gui.conn_store.append(nil)
            row[0] = data['host']
              row[1] = data['port']
              row[2] = data['state']
              row[3] = data['version']
              row[4] = data['block']
              row[5] = data['started']
              row[6] = data['user_agent']
              gui { conn_view.model = conn_store }
          elsif state == "disconnected"
            iter = nil
            gui.conn_store.each do |model,path,i|
              iter = i  if i[0] == data[0] && i[1] == data[1].to_s
            end
            if iter
              gui.conn_store.remove(iter)
              gui { conn_view.model = conn_store}
            end
          end
          i=0; gui.conn_store.each {i+=1};
          p = gui.notebook.get_nth_page(2)
          l = Gtk::Label.new("Connections (#{i})")
          gui { notebook.set_tab_label(p, l) }
        end

        on_disconnected do
          gui { status_network.push 0, "Offline" }
        end
      end
    end
  end

end
