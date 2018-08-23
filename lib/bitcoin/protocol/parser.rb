# encoding: ascii-8bit

module Bitcoin
  module Protocol
    # https://en.bitcoin.it/wiki/Protocol_documentation#Message_types
    class Parser
      attr_reader :stats

      def initialize(handler = nil)
        @h = handler || Handler.new
        @buf = ''
        @stats = { 'total_packets' => 0, 'total_bytes' => 0, 'total_errors' => 0 }
      end

      # rubocop:disable CyclomaticComplexity
      def process_pkt(command, payload)
        @stats['total_packets'] += 1
        @stats['total_bytes'] += payload.bytesize
        @stats[command] ? (@stats[command] += 1) : @stats[command] = 1
        case command
        when 'tx' then @h.on_tx(Tx.new(payload))
        when 'block' then @h.on_block(Block.new(payload))
        when 'headers' then parse_headers(payload)
        when 'inv' then parse_inv(payload, :put)
        when 'getdata' then parse_inv(payload, :get)
        when 'addr' then parse_addr(payload)
        when 'getaddr' then @h.on_getaddr if @h.respond_to?(:on_getaddr)
        when 'verack' then parse_verack
        when 'version' then parse_version(payload)
        when 'alert' then parse_alert(payload)
        when 'ping' then @h.on_ping(payload.unpack('Q')[0])
        when 'pong' then @h.on_pong(payload.unpack('Q')[0])
        when 'getblocks' then @h.on_getblocks(*parse_getblocks(payload)) \
          if @h.respond_to?(:on_getblocks)
        when 'getheaders' then @h.on_getheaders(*parse_getblocks(payload)) \
          if @h.respond_to?(:on_getheaders)
        when 'mempool' then handle_mempool_request(payload)
        when 'notfound' then handle_notfound_reply(payload)
        when 'merkleblock' then parse_mrkle_block(payload)
        when 'reject' then handle_reject(payload)
        else
          parse_error :unknown_packet, [command, payload.hth]
        end
      end
      # rubocop:enable CyclomaticComplexity

      def parse_headers(payload)
        return unless @h.respond_to?(:on_headers)
        buf = StringIO.new(payload)
        count = Protocol.unpack_var_int_from_io(buf)
        headers = Array.new(count) do
          break if buf.eof?
          b = Block.new
          b.parse_data_from_io(buf, true)
          b
        end
        @h.on_headers(headers)
      end

      # handles inv/getdata packets
      def parse_inv(payload, type = :put)
        count, payload = Protocol.unpack_var_int(payload)
        payload.each_byte.each_slice(36).with_index do |i, idx|
          hash = i[4..-1].reverse.pack('C32')
          case i[0]
          when 1
            type == :put ? @h.on_inv_transaction(hash) : @h.on_get_transaction(hash)
          when 2
            if type == :put
              if @h.respond_to?(:on_inv_block_v2)
                @h.on_inv_block_v2(hash, idx, count)
              else
                @h.on_inv_block(hash)
              end
            else
              @h.on_get_block(hash)
            end
          else
            parse_error :parse_inv, i.pack('C*')
          end
        end
      end

      def parse_addr(payload)
        _, payload = Protocol.unpack_var_int(payload)
        payload.each_byte.each_slice(30) do |i|
          begin
            @h.on_addr(Addr.new(i.pack('C*')))
          rescue StandardError
            parse_error(:addr, i.pack('C*'))
          end
        end
      end

      def parse_verack
        if @h.respond_to?(:on_verack)
          @h.on_verack
        else
          @h.respond_to?(:on_handshake_complete) ? @h.on_handshake_complete : nil
        end
      end

      def parse_version(payload)
        @version = Bitcoin::Protocol::Version.parse(payload)
        @h.on_version(@version)
      end

      def parse_alert(payload)
        # nop (https://github.com/lian/bitcoin-ruby/issues/268)
      end

      def parse_getblocks(payload)
        version, payload = payload.unpack('Va*')
        count, payload = Protocol.unpack_var_int(payload)
        buf, payload = payload.unpack("a#{count * 32}a*")
        hashes = buf.each_byte.each_slice(32).map { |i| i.reverse.pack('C32').hth }
        stop_hash = payload[0..32].reverse_hth
        [version, hashes, stop_hash]
      end

      # https://en.bitcoin.it/wiki/BIP_0035
      def handle_mempool_request(*_)
        return unless @version.fields[:version] >= 60_002 # Protocol version >= 60002
        return unless (
          @version.fields[:services] & Bitcoin::Protocol::Version::NODE_NETWORK
        ) == 1 # NODE_NETWORK bit set in Services
        @h.on_mempool if @h.respond_to?(:on_mempool)
      end

      def handle_notfound_reply(payload)
        return unless @h.respond_to?(:on_notfound)
        _, payload = Protocol.unpack_var_int(payload)
        payload.each_byte.each_slice(36) do |i|
          hash = i[4..-1].reverse.pack('C32')
          case i[0]
          when 1 then @h.on_notfound(:tx, hash)
          when 2 then @h.on_notfound(:block, hash)
          else
            parse_error(:notfound, [i.pack('C*'), hash])
          end
        end
      end

      def parse_mrkle_block(payload)
        return unless @h.respond_to?(:on_mrkle_block)
        b = Block.new
        b.parse_data_from_io(payload, :filtered)
        @h.on_mrkle_block(b)
      end

      def handle_reject(payload)
        return unless @h.respond_to?(:on_reject)
        @h.on_reject Bitcoin::Protocol::Reject.parse(payload)
      end

      def parse(buf)
        @buf += buf
        while parse_buffer; end
        @buf
      end

      def parse_buffer
        head_magic = Bitcoin.network[:magic_head]
        head_size  = 24
        return false if @buf.size < head_size

        magic, cmd, length, checksum = @buf.unpack('a4A12Va4')
        payload = @buf[head_size...head_size + length]

        if magic == head_magic

          if Digest::SHA256.digest(Digest::SHA256.digest(payload))[0...4] != checksum
            if (length < 50_000) && (payload.size < length)
              size_info = [payload.size, length].join('/')
              handle_stream_error(:debug, "chunked packet stream (#{size_info})")
            else
              handle_stream_error(:close, 'checksum mismatch')
            end
            return
          end
          @buf = @buf[head_size + length..-1] || ''

          process_pkt(cmd, payload)
        else
          handle_stream_error(:close, 'head_magic not found')
          @buf = ''
        end

        # not empty yet? parse more.
        !@buf[0].nil?
      end

      def handle_stream_error(type, msg)
        # TODO: replace by writing a real logger/exception handler
        case type
        when :close
          puts "closing packet stream (#{msg})"
        else
          puts [type, msg].inspect
        end
      end

      def parse_error(*err)
        @stats['total_errors'] += 1
        return unless @h.respond_to?(:on_error)
        @h.on_error(*err)
      end
    end
  end
end
