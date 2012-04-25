module Bitcoin::Gui
  class Connection < EM::Connection

    attr_reader :info

    def initialize gtk
      @gtk = gtk
      @gtk.node = self
      @buf = BufferedTokenizer.new("\x00")
    end

    def gui &block
      EM.next_tick do
        @gtk.instance_eval &block
      end
    end

    def post_init
      p 'connected'
      query("info")
      query("monitor", "block connection")
    end

    def query(cmd, args = "")
      puts "query: #{cmd}"
      send_data([cmd, args].to_json + "\x00")
    end

    def receive_data data
      @buf.extract(data).each do |packet|
        # p packet
        cmd, data = *JSON.load(packet)
        puts "data: #{cmd}"
        case cmd
        when 'info'
          text = "connections: #{data['connections']} | " +
            "addrs: #{data['addrs']} | uptime: #{data['uptime']}"
          gui { status_network.push 0, text }
          #EM::defer { sleep(1) && query("info") }

        when 'monitor'
          EM.defer do
            begin
              type, data = *data
              case type
              when "block"
                gui { status_store.push 0, "#{depth}" }
              when "tx"
              when "connection"
                next  unless data
                conn_type, data = *data
                if conn_type == "connected"
                  row = @gtk.conn_store.append(nil)
                  row[0] = data['host']
                  row[1] = data['port']
                  row[2] = data['state']
                  row[3] = data['version']
                  row[4] = data['block']
                  row[5] = data['started']
                  row[6] = data['user_agent']
                  gui { conn_view.model = conn_store }
                elsif conn_type == "disconnected"
                  iter = nil
                  @gtk.conn_store.each do |model,path,i|
                    iter = i  if i[0] == data[0] && i[1] == data[1].to_s
                  end
                  if iter
                    @gtk.conn_store.remove(iter)
                    gui { conn_view.model = conn_store}
                  end
                end
              when "addr"
              else
                puts "invalid datatype: #{type.inspect}"
              end
            rescue
              puts "Error reading command: #{cmd}(#{data.inspect})"
              p $!
              puts *$@
            end
          end
        end
      end
    end

    def unbind
      puts "disconnected"
    end

    def self.connect host, port, gtk
      EM.connect(host, port, self, gtk)
    end
  end
end
