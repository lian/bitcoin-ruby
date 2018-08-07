module Bitcoin
  # https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
  class BloomFilter
    SEED_SHIFT = 0xfba4c795
    BIT_MASK = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80].freeze

    MAX_FILTER_SIZE = 36_000
    MAX_HASH_FUNCS = 50

    # flags for filterload message
    BLOOM_UPDATE_NONE = 0
    BLOOM_UPDATE_ALL = 1
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2

    attr_reader :filter, :nfunc, :tweak

    def initialize(elements, fp_rate, tweak)
      init_filter(elements, fp_rate)
      @tweak = tweak
    end

    def add_data(data)
      @nfunc.times.each do |fi|
        idx = calc_index(data, fi)
        i = idx / 8
        @filter[i] = (@filter[i].ord | BIT_MASK[idx % 8]).chr
      end
    end

    def contains?(data)
      @nfunc.times.all? do |fi|
        idx = calc_index(data, fi)
        i = idx / 8
        @filter[i].ord & BIT_MASK[idx % 8] != 0
      end
    end

    def add_address(address)
      add_data(Bitcoin.hash160_from_address(address).htb)
    end

    def add_outpoint(prev_tx_hash, prev_output)
      add_data(prev_tx_hash.htb_reverse + [prev_output].pack('V'))
    end

    private

    #
    # calculate filter size and number of funcs.
    # See: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
    #
    def init_filter(elements, fp_rate)
      ln2 = Math.log(2)

      # using #ceil instead of #floor may be better, but it's bitcoinj's way

      calc_m = (-Math.log(fp_rate) * elements / ln2 / ln2 / 8).floor
      @filter_size = [1, [calc_m, MAX_FILTER_SIZE].min].max
      @filter = "\x00" * @filter_size

      calc_k = (@filter_size * 8 * ln2 / elements).floor
      @nfunc = [1, [calc_k, MAX_HASH_FUNCS].min].max
    end

    def rotate_left32(x, r)
      (x << r) | (x >> (32 - r))
    end

    #
    # calculate MurmurHash3
    # See: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
    #
    def calc_index(data, hash_index)
      object = data.bytes
      h1 = (hash_index * SEED_SHIFT + @tweak) & 0xffffffff
      c1 = 0xcc9e2d51
      c2 = 0x1b873593

      num_blocks = (object.length / 4) * 4
      i = 0
      # body
      while i < num_blocks
        k1 = (object[i] & 0xFF) |
             ((object[i + 1] & 0xFF) << 8) |
             ((object[i + 2] & 0xFF) << 16) |
             ((object[i + 3] & 0xFF) << 24)

        k1 *= c1
        k1 &= 0xffffffff
        k1 = rotate_left32(k1, 15)
        k1 *= c2
        k1 &= 0xffffffff

        h1 ^= k1
        h1 = rotate_left32(h1, 13)
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

        i += 4
      end

      k1 = 0
      flg = object.length & 3
      k1 ^= (object[num_blocks + 2] & 0xff) << 16 if flg >= 3
      k1 ^= (object[num_blocks + 1] & 0xff) << 8 if flg >= 2
      if flg >= 1
        k1 ^= (object[num_blocks] & 0xff)
        k1 *= c1
        k1 &= 0xffffffff
        k1 = rotate_left32(k1, 15)
        k1 *= c2
        k1 &= 0xffffffff
        h1 ^= k1
      end

      # finalization
      h1 ^= object.length
      h1 ^= h1 >> 16
      h1 *= 0x85ebca6b
      h1 &= 0xffffffff
      h1 ^= h1 >> 13
      h1 *= 0xc2b2ae35
      h1 &= 0xffffffff
      h1 ^= h1 >> 16

      (h1 & 0xffffffff) % (@filter_size * 8)
    end
  end
end
