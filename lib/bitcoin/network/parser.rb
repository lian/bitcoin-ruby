module Bitcoin
  module Protocol

    class Parser
      def initialize(handler=nil)
        @h = handler || Handler.new
        @buf = ""
      end

      # handles inv/getdata packets
      #
      def parse_inv(payload, type=:put)
        count, payload = Protocol.read_var_int(payload)
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
        count, payload = Protocol.read_var_int(payload)
        payload.each_byte.each_slice(30){|i|
          @h.on_addr( Addr.new(i.pack("C*")) )
        }
      end

      def process_pkt(command, payload)
        case command
        when 'tx';       @h.on_tx( Tx.new(payload) )
        when 'block';    @h.on_block( Block.new(payload) )
        when 'inv';      parse_inv(payload, :put)
        when 'getdata';  parse_inv(payload, :get)
        when 'addr';     parse_addr(payload)
        when 'verack';   @h.on_handshake_complete # nop
        when 'version';  parse_version(payload)
        else
          p ['unkown-packet', command, payload]
        end
      end

      def parse_version(payload)
        @h.on_version(payload)
      end

      def parse(buf)
        @buf += buf
        while parse_buffer; end
        @buf
      end

      def parse_buffer
        head_magic = "\xF9\xBE\xB4\xD9"
        head_size  = 24
        return false if @buf.size <= head_size

        magic, cmd, length, checksum = @buf.unpack("a4A12Ia4")
        payload = @buf[head_size...head_size+length]

        unless magic == head_magic
          handle_error(:close, "head_magic not found")
        else

          if ['version', 'verack'].include?(cmd)
            head_size -= 4
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
          puts "closing packet stream (#{msg})"
        else
          p [type, msg]
        end
      end
    end # Parser

  end
end
