module Bitcoin
  module Protocol

    class Handler
      def on_inv_transaction(hash)
        p ['inv transaction', hth(hash)]
      end

      def on_inv_block(hash)
        p ['inv block', hth(hash)]
      end

      def on_get_transaction(hash)
        p ['get transaction', hth(hash)]
      end

      def on_get_block(hash)
        p ['get block', hth(hash)]
      end

      def on_addr(addr)
        p ['addr', addr, addr.alive?]
      end

      def on_tx(tx)
        p ['tx', tx]
      end

      def on_block(block)
        #p ['block', block]
        puts block.to_json
      end

      def hth(h); h.unpack("H*")[0]; end
    end

  end
end
