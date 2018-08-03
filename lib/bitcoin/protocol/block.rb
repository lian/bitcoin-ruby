# encoding: ascii-8bit

module Bitcoin
  module Protocol
    # https://en.bitcoin.it/wiki/Protocol_documentation#block
    class Block
      BLOCK_VERSION_DEFAULT     = (1 << 0)
      BLOCK_VERSION_AUXPOW      = (1 << 8)
      BLOCK_VERSION_CHAIN_START = (1 << 16)
      BLOCK_VERSION_CHAIN_END   = (1 << 30)

      # block hash
      attr_accessor :hash

      # previous block hash
      attr_accessor :prev_block_hash
      alias prev_block prev_block_hash
      def prev_block=(hash)
        @prev_block_hash = hash
      end

      # transactions (Array of Tx)
      attr_accessor :tx

      # merkle root
      attr_accessor :mrkl_root

      # block generation time
      attr_accessor :time

      # difficulty target bits
      attr_accessor :bits

      # nonce (number counted when searching for block hash matching target)
      attr_accessor :nonce

      # version (usually 1)
      attr_accessor :ver

      # raw protocol payload
      attr_accessor :payload

      # AuxPow linking the block to a merge-mined chain
      attr_accessor :aux_pow

      attr_reader :partial_merkle_tree

      alias transactions tx

      # compare to another block
      def ==(other)
        @hash == other.hash
      end

      def binary_hash
        [@hash].pack('H*')
      end

      def prev_block_hex
        @prev_block_hex ||= @prev_block_hash.reverse.unpack('H*')[0]
      end

      # create block from raw binary +data+
      def initialize(data = nil)
        @tx = []
        @payload = nil
        parse_data_from_io(data) if data
      end

      # parse raw binary data
      def parse_data(data)
        buf = parse_data_from_io(data)
        buf.eof? ? true : buf.read
      end

      # parse raw binary data
      def parse_data_from_io(buf, header_only = false)
        buf = buf.is_a?(String) ? StringIO.new(buf) : buf
        @ver, @prev_block_hash, @mrkl_root, @time, @bits, @nonce = buf.read(80).unpack('Va32a32VVV')
        recalc_block_hash

        if !Bitcoin.network[:auxpow_chain_id].nil? && (@ver & BLOCK_VERSION_AUXPOW) > 0
          @aux_pow = AuxPow.new(nil)
          @aux_pow.parse_data_from_io(buf)
        end

        return buf if buf.eof?

        return parse_filtered_header(buf) if header_only == :filtered

        tx_size = Protocol.unpack_var_int_from_io(buf)
        @tx_count = tx_size
        return buf if header_only

        tx_size.times do
          break if payload == true
          return buf if buf.eof?

          t = Tx.new(nil)
          t.parse_data_from_io(buf)
          @tx << t
        end

        @payload = to_payload
        buf
      end

      def parse_filtered_header(buf)
        @tx_count = buf.read(4).unpack('V')[0]

        nhashes = Protocol.unpack_var_int_from_io(buf)
        hashes = []
        nhashes.times do
          hashes << buf.read(256 / 8)
        end

        nflags = Protocol.unpack_var_int_from_io(buf)
        flags = buf.read(nflags)

        @partial_merkle_tree = PartialMerkleTree.new(@tx_count, hashes, flags)
        @partial_merkle_tree.assign_value

        buf
      end

      # recalculate the block hash
      def recalc_block_hash
        @hash = Bitcoin.block_hash(
          @prev_block_hash.reverse_hth, @mrkl_root.reverse_hth, @time, @bits, @nonce, @ver
        )
      end

      def recalc_block_scrypt_hash
        @scrypt_hash = Bitcoin.block_scrypt_hash(
          @prev_block_hash.reverse_hth, @mrkl_root.reverse_hth, @time, @bits, @nonce, @ver
        )
      end

      def recalc_mrkl_root
        @mrkl_root = if partial_merkle_tree
                       partial_merkle_tree.root.value.htb_reverse
                     else
                       Bitcoin.hash_mrkl_tree(@tx.map(&:hash)).last.htb_reverse
                     end
      end

      # verify mrkl tree
      def verify_mrkl_root
        if partial_merkle_tree
          partial_merkle_tree.valid_tree?(@mrkl_root.reverse_hth)
        else
          @mrkl_root.reverse_hth == Bitcoin.hash_mrkl_tree(@tx.map(&:hash)).last
        end
      end

      def tx_hashes
        if partial_merkle_tree
          partial_merkle_tree.tx_hashes
        else
          @tx.map(&:hash)
        end
      end

      # get the block header info
      # [<version>, <prev_block>, <merkle_root>, <time>, <bits>, <nonce>, <txcount>, <size>]
      def header_info
        [
          @ver, @prev_block_hash.reverse_hth, @mrkl_root.reverse_hth,
          Time.at(@time), @bits, @nonce, @tx.size, @payload.size
        ]
      end

      # convert to raw binary format
      def to_payload
        @aux_pow ||= nil
        head = [@ver, @prev_block_hash, @mrkl_root, @time, @bits, @nonce].pack('Va32a32VVV')
        head << @aux_pow.to_payload if @aux_pow
        return head if @tx.empty?

        head << Protocol.pack_var_int(@tx.size)
        @tx.each { |tx| head << tx.to_payload }
        head
      end

      # convert to ruby hash (see also #from_hash)
      def to_hash(options = {})
        h = {
          'hash' => @hash, 'ver' => @ver,
          'prev_block' => @prev_block_hash.reverse_hth, 'mrkl_root' => @mrkl_root.reverse_hth,
          'time' => @time, 'bits' => @bits, 'nonce' => @nonce,
          'n_tx' => @tx.size, 'size' => (@payload || to_payload).bytesize,
          'tx' => @tx.map { |i| i.to_hash(options) },
          'mrkl_tree' => Bitcoin.hash_mrkl_tree(@tx.map(&:hash))
        }
        h['aux_pow'] = @aux_pow.to_hash if @aux_pow
        h
      end

      def size
        payload.bytesize
      end

      def hextarget
        Bitcoin.decode_compact_bits(@bits)
      end

      def decimaltarget
        Bitcoin.decode_compact_bits(@bits).to_i(16)
      end

      def difficulty
        Bitcoin.block_difficulty(@bits)
      end

      # introduced in block version 2 by BIP_0034
      # blockchain height as seen by the block itself.
      # do not trust this value, instead verify with chain storage.
      def bip34_block_height(height = nil)
        return nil unless @ver >= 2
        if height # generate height binary
          buf = [height].pack('V').gsub(/\x00+$/, '')
          [buf.bytesize, buf].pack('Ca*')
        else
          coinbase = @tx.first.inputs.first.script_sig
          coinbase[1..coinbase[0].ord].ljust(4, "\x00").unpack('V').first
        end
      rescue StandardError
        nil
      end

      # convert to json representation as seen in the block explorer.
      # (see also #from_json)
      def to_json(options = { space: '' }, *_)
        JSON.pretty_generate(to_hash(options), options)
      end

      # write json representation to a file
      # (see also #to_json)
      def to_json_file(path)
        File.open(path, 'wb') { |f| f.print to_json; }
      end

      # parse ruby hash (see also #to_hash)
      def self.from_hash(h, do_raise = true)
        blk = new(nil)
        blk.instance_eval do
          @ver, @time, @bits, @nonce = h.values_at('ver', 'time', 'bits', 'nonce')
          @prev_block_hash, @mrkl_root = h.values_at('prev_block', 'mrkl_root').map(&:htb_reverse)

          if do_raise && h['hash'] != recalc_block_hash
            raise "Block hash mismatch! Claimed: #{h['hash']}, Actual: #{@hash}"
          end

          @aux_pow = AuxPow.from_hash(h['aux_pow']) if h['aux_pow']

          h['tx'].each { |tx| @tx << Tx.from_hash(tx, do_raise) }
          if h['tx'].any? && do_raise && !verify_mrkl_root
            raise "Block merkle root mismatch! Block: #{h['hash']}"
          end
        end
        blk
      end

      # convert ruby hash to raw binary
      def self.binary_from_hash(h)
        from_hash(h).to_payload
      end

      # parse json representation (see also #to_json)
      def self.from_json(json_string)
        from_hash(JSON.parse(json_string))
      end

      # convert json representation to raw binary
      def self.binary_from_json(json_string)
        from_json(json_string).to_payload
      end

      # convert header to json representation.
      def header_to_json(options = { space: '' })
        h = to_hash
        %w[tx mrkl_tree].each { |k| h.delete(k) }
        JSON.pretty_generate(h, options)
      end

      # block header binary output
      def block_header
        [
          @ver, @prev_block_hash, @mrkl_root, @time, @bits, @nonce, Protocol.pack_var_int(0)
        ].pack('Va32a32VVVa*')
      end

      # read binary block from a file
      def self.from_file(path)
        new(Bitcoin::Protocol.read_binary_file(path))
      end

      # read json block from a file
      def self.from_json_file(path)
        from_json(Bitcoin::Protocol.read_binary_file(path))
      end

      # get the (statistical) amount of work that was needed to generate this block.
      def block_work
        target = Bitcoin.decode_compact_bits(@bits).to_i(16)
        return 0 if target <= 0
        (2**256) / (target + 1)
      end
    end
  end
end
