module Bitcoin::Protocol

  class MerkleBlock < Block

    attr_accessor :hashes, :flags, :depth, :chain, :work

    def initialize data = nil, header_only = true
      @tx, @tx_count, @hashes, @flags = [], 0, [], []
      return  unless data
      data = StringIO.new(data)  unless data.is_a?(StringIO)

      data = parse_data_from_io(data, header_only)
      return  if data.eof?

      n_hashes = Bitcoin::P.unpack_var_int_from_io(data)
      n_hashes.times { @hashes << data.read(32).reverse.hth }
      n_flags = Bitcoin::P.unpack_var_int_from_io(data)
      n_flags.times { @flags << data.read(1).ord }
    end


    def to_payload
      payload = super()
      payload += [@tx_count || tx.count].pack("V")  if @tx_count
      return payload  unless @hashes
      payload += Bitcoin::P.pack_var_int(@hashes.size)
      payload += @hashes.map(&:htb).map(&:reverse).join
      return payload  unless @flags
      payload += Bitcoin::P.pack_var_int(@flags.size)
      payload += @flags.pack("C*")
      payload
    end

    def self.from_block_payload data
      b = new data
      b.hashes = b.tx.map(&:hash).map(&:htb)
      b.tx_count = b.tx.count
      # TODO: flags
      b
    end

    def self.from_block blk, header_only = true
      b = new blk.to_payload, header_only
      b.tx = blk.tx
      b.hashes = b.tx.map(&:hash)
      b.tx_count = b.tx.count
      # TODO: flags
      b
    end

  end

end
