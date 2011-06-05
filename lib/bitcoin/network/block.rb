module Bitcoin
  module Protocol

    class Block
      attr_reader :hash, :payload, :tx

      def initialize(data)
        parse_data(data) if data
      end

      def parse_data(data)
        @payload, @size = data, data.size
        @ver, @prev_block, @mrkl_root, @time, @bits, @nonce, payload = data.unpack("Ia32a32IIIa*")
        @hash = Bitcoin.block_hash(hth(@prev_block), hth(@mrkl_root), @time, @bits, @nonce, @ver)
        @tx = []

        tx_size, payload = Protocol.read_var_int(payload)
        (0...tx_size).each{  break if payload == true
          t = Tx.new(nil)
          payload = t.parse_data(payload)
          @tx << t
        }
        #p header_info
        #p @tx.map{|i| i.hash }
      end

      def header_info
        [@ver, hth(@prev_block), hth(@mrkl_root), Time.at(@time), @bits, @nonce, @tx.size, @size]
      end

      def hth(h); h.reverse.unpack("H*")[0]; end

      def to_hash
        {
          'hash' => @hash, 'ver' => @ver,
          'prev_block' => hth(@prev_block), 'mrkl_root' => hth(@mrkl_root),
          'time' => @time, 'bits' => @bits, 'nonce' => @nonce,
          'n_tx' => @tx.size, 'size' => @payload.bytesize,
          'tx' => @tx.map{|i| i.to_hash },
          'mrkl_tree' => Bitcoin.hash_mrkl_tree( @tx.map{|i| i.hash } )
        }
      end

      # generates rawblock json as seen in the block explorer.
      def to_json
        JSON.pretty_generate( to_hash )
      end
    end

  end
end
