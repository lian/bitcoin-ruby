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
            gui do
              data.each_with_index do |pair, i|
                conn_store.set_value(row, i, pair[1] || "")
              end
            end
          elsif state == "disconnected"
            gui do
              valid, i = conn_store.get_iter_first
              while valid
                host = conn_store.get_value(i, 0).get_string
                port = conn_store.get_value(i, 1).get_int
                if host == data[0] && port == data[1]
                  conn_store.remove(i)
                  break
                end
                valid = conn_store.iter_next(i.to_ptr)
              end
            end
          end

          gui do
            size = 0
            v, i = conn_store.get_iter_first
            while v
              size += 1
              v = conn_store.iter_next(i.to_ptr)
            end

            p = notebook.get_nth_page(2)
            l = Gtk::Label.new("Connections (#{size})")
            notebook.set_tab_label(p, l)
          end
        end

        on_disconnected do
          gui { status_network.push 0, "Offline" }
        end
      end
    end
  end

end
