# encoding: ascii-8bit

module Bitcoin
  # Ruby reference implementation: https://github.com/sipa/bech32/tree/master/ref/c
  module Bech32
    CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'.unpack('C*')
    CHARSET_REV = [
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
      -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
      1,  0,  3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
      -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
      1,  0,  3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
    ].freeze

    class << self
      def polymod_step(pre)
        b = pre >> 25
        ((pre & 0x1FFFFFF) << 5) ^ \
          (-((b >> 0) & 1) & 0x3b6a57b2) ^ \
          (-((b >> 1) & 1) & 0x26508e6d) ^ \
          (-((b >> 2) & 1) & 0x1ea119fa) ^ \
          (-((b >> 3) & 1) & 0x3d4233dd) ^ \
          (-((b >> 4) & 1) & 0x2a1462b3)
      end

      def encode(hrp, data)
        buf = []
        chk = 1

        hrp.unpack('C*').each do |ch|
          return nil if ch < 33 || ch > 126
          return nil if ch >= 'A'.ord && ch <= 'Z'.ord
          chk = polymod_step(chk) ^ (ch >> 5)
        end

        return nil if (hrp.bytesize + 7 + data.size) > 90

        chk = polymod_step(chk)
        hrp.unpack('C*').each do |ch|
          chk = polymod_step(chk) ^ (ch & 0x1f)
          buf << ch
        end

        buf << '1'.ord

        data.each do |i|
          return nil if (i >> 5) != 0
          chk = polymod_step(chk) ^ i
          buf << CHARSET[i]
        end

        6.times do
          chk = polymod_step(chk)
        end

        chk ^= 1

        6.times do |i|
          buf << CHARSET[(chk >> ((5 - i) * 5)) & 0x1f]
        end

        buf.pack('C*')
      end

      # rubocop:disable CyclomaticComplexity,PerceivedComplexity
      def decode(input)
        chk = 1
        input_len = input.bytesize
        have_lower = false
        have_upper = false

        return nil if input_len < 8 || input_len > 90

        data_len = 0
        data_len += 1 while data_len < input_len && input[(input_len - 1) - data_len] != '1'

        hrp_len = input_len - (1 + data_len)
        return nil if hrp_len < 1 || data_len < 6

        hrp = []
        hrp_len.times do |i|
          ch = input[i].ord
          return nil if ch < 33 || ch > 126

          if ch >= 'a'.ord && ch <= 'z'.ord
            have_lower = true
          elsif ch >= 'A'.ord && ch <= 'Z'.ord
            have_upper = true
            ch = (ch - 'A'.ord) + 'a'.ord
          end

          hrp << ch
          chk = polymod_step(chk) ^ (ch >> 5)
        end

        chk = polymod_step(chk)

        hrp_len.times do |i|
          chk = polymod_step(chk) ^ (input[i].ord & 0x1f)
        end

        data = []
        i = hrp_len + 1
        while i < input_len
          ch = input[i].ord
          v = (ch & 0x80) != 0 ? -1 : CHARSET_REV[ch]

          have_lower = true if ch >= 'a'.ord && ch <= 'z'.ord
          have_upper = true if ch >= 'A'.ord && ch <= 'Z'.ord
          return nil if v == -1

          chk = polymod_step(chk) ^ v
          data << v if (i + 6) < input_len
          i += 1
        end

        return nil if have_lower && have_upper
        return nil if chk != 1

        [hrp.pack('C*'), data]
      end
      # rubocop:enable CyclomaticComplexity,PerceivedComplexity

      # Utility for converting bytes of data between bases. These is used for
      # BIP 173 address encoding/decoding to convert between sequences of bytes
      # representing 8-bit values and groups of 5 bits. Conversions may be padded
      # with trailing 0 bits to the nearest byte boundary. Returns nil if
      # conversion requires padding and pad is false.
      #
      # For example:
      #
      #   convert_bits("\xFF\xFF", from_bits: 8, to_bits: 5, pad: true)
      #     => "\x1F\x1F\x1F\10"
      #
      # See https://github.com/bitcoin/bitcoin/blob/595a7bab23bc21049526229054ea1fff1a29c0bf/src/utilstrencodings.h#L154
      def convert_bits(chunks, from_bits:, to_bits:, pad:)
        output_mask = (1 << to_bits) - 1
        buffer_mask = (1 << (from_bits + to_bits - 1)) - 1

        buffer = 0
        bits = 0

        output = []
        chunks.each do |chunk|
          buffer = ((buffer << from_bits) | chunk) & buffer_mask
          bits += from_bits
          while bits >= to_bits
            bits -= to_bits
            output << ((buffer >> bits) & output_mask)
          end
        end

        output << ((buffer << (to_bits - bits)) & output_mask) if pad && bits > 0

        if !pad && (bits >= from_bits || ((buffer << (to_bits - bits)) & output_mask) != 0)
          return nil
        end

        output
      end
    end
  end
end
