require "bitcoin"

# Bitcoin compatible Bloom Filter.
# Thanks to https://github.com/jgarzik/python-bitcoinlib
class Bitcoin::BloomFilter

  MAX_SIZE = 36000
  MAX_HASH_FUNCS = 50

  LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
  LN2 = 0.6931471805599453094172321214581765680755001343602552

  # Tells the remote node our desired update behaviour when transactions are matched
  UPDATE_FLAGS = [
    # don't adjust the filter when a match is found.
    :update_none,

    # if the filter matches any data element in a scriptPubKey the outpoint is
    # serialized and inserted into the filter.
    :update_all,

    # the outpoint is inserted into the filter only if a data element in the
    # scriptPubKey is matched, and that script is of the standard "pay to pubkey" or
    # "pay to multisig" forms.
    :update_p2pubkey_only
  ]

  attr_reader :size, :fp_rate, :tweak, :flags, :hash_funcs, :data

  def initialize size, fp_rate, tweak, flags = :update_none
    @data = Array.new([-1 / LN2SQUARED * size * Math.log(fp_rate), MAX_SIZE * 8].min / 8, 0)
    @hash_funcs = [@data.size * 8 / size * LN2, MAX_HASH_FUNCS].min.to_i
    @size, @fp_rate, @tweak, @flags = size, fp_rate, tweak, flags
    @bit_mask = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
  end

  def bloom_hash(num, data)
    seed = ((num * 0xFBA4C795) + @tweak) & 0xFFFFFFFF
    murmurhash3(seed, data) % (@data.size * 8)
  end

  # Insert an element in the filter.
  def insert(elem)
    return  if @data.size == 1 && @data[0] == 0xff
    for i in (0...@hash_funcs)
      nIndex = bloom_hash(i, elem)
      @data[nIndex >> 3] |= @bit_mask[7 & nIndex]
    end
  end

  # Test if the filter contains an element
  def contains(elem)
    return true  if @data.size == 1 && @data[0] == 0xff
    for i in (0...@hash_funcs)
      nIndex = bloom_hash(i, elem)
      return false  unless (@data[nIndex >> 3] & @bit_mask[7 & nIndex]) > 0
    end
    true
  end

  def IsWithinSizeConstraints
    @data.size <= MAX_SIZE && @hash_funcs <= MAX_HASH_FUNCS
  end

  def IsRelevantAndUpdate(tx, tx_hash)
    # Not useful for a client, so not implemented yet.
    raise "BloomFilter#IsRelevantAndUpdate not implemented"
  end

  def serialize
    (ser_string(@data.map(&:chr).join) + [@hash_funcs, @tweak, UPDATE_FLAGS.index(@flags)].pack("IIC")).unpack("H*")[0]
  end

  def deserialize str
    str = str.htb
    @data, str = *deser_string(str)
    @data = @data.split("").map(&:ord)
    @hash_funcs, @tweak, @flags = *str.unpack("IIC")
    @flags = UPDATE_FLAGS[@flags]
  end

  def ser_string(s)
    if s.bytesize < 253
      return s.bytesize.chr + s
    elsif s.bytesize < 0x1000
      return 253.chr + [s.bytesize].pack("v") + s # struct.pack(b"<H", len(s))
    elsif s.bytesize < 0x100000000
      return 254.chr + [s.bytesize].pack("I") + s # struct.pack(b"<I", len(s))
    end
    255.chr + [s.bytesize].pack("Q") + s # struct.pack(b"<Q", len(s))
  end

  def deser_string(str)
    nit, str = *str.unpack("Ca*")
    if nit == 253
      nit, str = *str.unpack("va*")
    elsif nit == 254
      nit, str = *str.unpack("Ia*")
    elsif nit == 255
      nit, str = *str.unpack("Qa*")
    end
    [str[0...nit], str[nit..-1]]
  end

  def rotl32(x, r)
    raise "x too big."  unless x <= 0xFFFFFFFF
    ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))
  end

  def murmurhash3(seed, data)
    raise "hash_seed too big."  unless seed <= 0xFFFFFFFF

    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    # body
    i = 0
    while i < data.bytesize - data.bytesize % 4 && data.bytesize - i >= 4

      k1 = data[i..i+4].unpack("V")[0]

      k1 = (k1 * c1) & 0xFFFFFFFF
      k1 = rotl32(k1, 15)
      k1 = (k1 * c2) & 0xFFFFFFFF

      h1 ^= k1
      h1 = rotl32(h1, 13)
      h1 = (((h1*5) & 0xFFFFFFFF) + 0xe6546b64) & 0xFFFFFFFF

      i += 4
    end

    # tail
    k1 = 0
    j = (data.bytesize / 4) * 4

    k1 ^= data[j+2].ord << 16  if data.bytesize & 3 >= 3
    k1 ^= data[j+1].ord << 8  if data.bytesize & 3 >= 2
    k1 ^= data[j].ord  if data.bytesize & 3 >= 1

    k1 &= 0xFFFFFFFF
    k1 = (k1 * c1) & 0xFFFFFFFF
    k1 = rotl32(k1, 15)
    k1 = (k1 * c2) & 0xFFFFFFFF
    h1 ^= k1

    # finalization
    h1 ^= data.bytesize & 0xFFFFFFFF
    h1 ^= (h1 & 0xFFFFFFFF) >> 16
    h1 *= 0x85ebca6b
    h1 ^= (h1 & 0xFFFFFFFF) >> 13
    h1 *= 0xc2b2ae35
    h1 ^= (h1 & 0xFFFFFFFF) >> 16

    h1 & 0xFFFFFFFF
  end

end
