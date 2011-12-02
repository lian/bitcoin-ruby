module Bitcoin
  module Protocol

    class Block
      attr_reader :hash, :payload, :tx

      def initialize(data)
        @tx = []
        parse_data(data) if data
      end

      def parse_data(data)
        @payload, @size = data, data.size
        @ver, @prev_block, @mrkl_root, @time, @bits, @nonce, payload = data.unpack("Ia32a32IIIa*")
        recalc_block_hash

        tx_size, payload = Protocol.unpack_var_int(payload)
        (0...tx_size).each{  break if payload == true
          t = Tx.new(nil)
          payload = t.parse_data(payload)
          @tx << t
        }
        #p header_info
        #p @tx.map{|i| i.hash }
      end

      def recalc_block_hash
        @hash = Bitcoin.block_hash(hth(@prev_block), hth(@mrkl_root), @time, @bits, @nonce, @ver)
      end

      def header_info
        [@ver, hth(@prev_block), hth(@mrkl_root), Time.at(@time), @bits, @nonce, @tx.size, @size]
      end

      def hth(h); h.reverse.unpack("H*")[0]; end
      def htb(s); [s].pack('H*').reverse; end


      def to_payload
        head = [@ver, @prev_block, @mrkl_root, @time, @bits, @nonce].pack("Ia32a32III")
        [head, Protocol.pack_var_int(@tx.size), @tx.map(&:to_payload).join].join
      end

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
        JSON.pretty_generate( to_hash, :space => '' )
      end

      def self.from_hash(h)
        blk = new(nil)
        blk.instance_eval{
          @ver, @time, @bits, @nonce = h.values_at('ver', 'time', 'bits', 'nonce')
          @prev_block, @mrkl_root = h.values_at('prev_block', 'mrkl_root').map{|i| htb(i) }
          recalc_block_hash
          h['tx'].each{|tx| @tx << Tx.from_hash(tx) }
        }
        blk
      end

      def self.binary_from_hash(h); from_hash(h).to_payload; end
      def self.from_json(json_string); from_hash( JSON.load(json_string) ); end
      def self.binary_from_json(json_string); from_json(json_string).to_payload; end
    end

  end
end
