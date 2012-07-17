module Bitcoin
  module Protocol

    class Parser

      def initialize(handler=nil)
        @h = handler || Handler.new
        @buf = ""
      end

      def log
        @log ||= Bitcoin::Logger.create("parser")
      end

      # handles inv/getdata packets
      #
      def parse_inv(payload, type=:put)
        count, payload = Protocol.unpack_var_int(payload)
        payload.each_byte.each_slice(36){|i|
          hash = i[4..-1].reverse.pack("C32")
          case i[0]
          when 1
            if type == :put
              @h.on_inv_transaction(hash)
            else
              @h.on_get_transaction(hash)
            end
          when 2
            if type == :put
              @h.on_inv_block(hash)
            else
              @h.on_get_block(hash)
            end
          else
            p ['parse_inv error', i]
          end
        }
      end

      def hth(h); h.unpack("H*")[0]; end

      def parse_addr(payload)
        count, payload = Protocol.unpack_var_int(payload)
        payload.each_byte.each_slice(30){|i|
          begin
            addr = Addr.new(i.pack("C*"))
          rescue
            puts "Error parsing addr: #{i.inspect}"
          end
          @h.on_addr( addr )
        }
      end

      def parse_headers(payload)
        count, payload = Protocol.unpack_var_int(payload)
        idx = 0
        headers = count.times.map{ Block.new(payload[idx..idx+=81]) }
        @h.on_headers(headers)
      end

      def parse_getblocks(payload)
        version, payload = payload.unpack('a4a*')
        count,   payload = Protocol.unpack_var_int(payload)
        buf,     payload = payload.unpack("a#{count*32}a*")
        hashes    = buf.each_byte.each_slice(32).map{|i| hash = Protocol.hth(i.reverse.pack("C32")) }
        stop_hash = Protocol.hth(payload[0..32].reverse)
        [version, hashes, stop_hash]
      end

      def process_pkt(command, payload)
        case command
        when 'tx';       @h.on_tx( Tx.new(payload) )
        when 'block';    @h.on_block( Block.new(payload) )
        when 'headers';  parse_headers(payload)
        when 'inv';      parse_inv(payload, :put)
        when 'getdata';  parse_inv(payload, :get)
        when 'addr';     parse_addr(payload)
        when 'verack';   @h.on_handshake_complete # nop
        when 'version';  parse_version(payload)
        when 'alert';    parse_alert(payload)
        when 'ping';     @h.on_ping(payload.unpack("Q")[0])
        when 'pong';     @h.on_pong(payload.unpack("Q")[0])
        when 'getblocks';   @h.on_getblocks(*parse_getblocks(payload))
        when 'getheaders';  @h.on_getheaders(*parse_getblocks(payload))
        else
          p ['unkown-packet', command, payload]
        end
      end

      def parse_version(payload)
        version = Bitcoin::Protocol::Version.parse(payload)
        @h.on_version(version)
      end

      def parse_alert(payload)
        return unless @h.respond_to?(:on_alert)
        @h.on_alert Bitcoin::Protocol::Alert.parse(payload)
      end

      def parse(buf)
        @buf += buf
        while parse_buffer; end
        @buf
      end

      def parse_buffer
        head_magic = Bitcoin::network[:magic_head]
        head_size  = 24
        return false if @buf.size <= head_size

        magic, cmd, length, checksum = @buf.unpack("a4A12Ia4")
        payload = @buf[head_size...head_size+length]

        unless magic == head_magic
          handle_error(:close, "head_magic not found")
          @buf = ''
        else

          if Digest::SHA256.digest(Digest::SHA256.digest( payload ))[0...4] != checksum
            if (length < 50000) && (payload.size < length)
              size_info = [payload.size, length].join('/')
              handle_error(:debug, "chunked packet stream (#{size_info})")
            else
              handle_error(:close, "checksum mismatch")
            end
            return
          end
          @buf = @buf[head_size+length..-1] || ""

          process_pkt(cmd, payload)
        end

        # not empty yet? parse more.
        @buf[0] != nil
      end

      def handle_error(type, msg)
        case type
        when :close
          log.debug {"closing packet stream (#{msg})"}
        else
          log.debug { [type, msg] }
        end
      end
    end # Parser

  end
end
