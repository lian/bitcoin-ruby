# encoding: ascii-8bit

module Bitcoin
  module Protocol
    # https://en.bitcoin.it/wiki/Protocol_documentation#Message_types
    class Handler
      def on_inv_transaction(hash)
        p ['inv transaction', hash.hth]
      end

      def on_inv_block(hash)
        p ['inv block', hash.hth]
      end

      def on_get_transaction(hash)
        p ['get transaction', hash.hth]
      end

      def on_get_block(hash)
        p ['get block', hash.hth]
      end

      def on_addr(addr)
        p ['addr', addr, addr.alive?]
      end

      def on_tx(tx)
        p ['tx', tx]
      end

      def on_block(block)
        # p ['block', block]
        puts block.to_json
      end

      def on_error(message, payload)
        p ['error', message, payload]
      end
    end
  end
end
