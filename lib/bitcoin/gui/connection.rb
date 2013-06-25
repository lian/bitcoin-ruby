# encoding: ascii-8bit

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
      @gui.node = Bitcoin::Network::CommandClient.connect(host, port, gui) do

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
            gui.conn_view.connected(data)
          elsif state == "disconnected"
            gui.conn_view.disconnected(data)
          end

          gui do
            size = 0
            v, i = conn_view.model.get_iter_first
            while v
              size += 1
              v = conn_view.model.iter_next(i.to_ptr)
            end

            p = notebook.get_nth_page(2)
            l = Gtk::Label.new("Connections (#{size})")
            notebook.set_tab_label(p, l)
          end
        end

        on_disconnected do
          if @connection_attempts == 4
            gui do
              message(:warning, "Node not available", "The bitcoin node is not running " +
                "or not reachable.\nYou can use the wallet to handle keys but you won't " +
                "be able to send/receive transactions.", [:ok])
            end
          end
          gui.status_network.push 0, "Offline"
        end
      end
    end
  end

end
