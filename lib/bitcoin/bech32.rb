# encoding: ascii-8bit

# Copyright (c) 2017 Shigeyuki Azuchi
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# Bech32 encoding is used for newer Bitcoin address formats, as specified in
# BIP 173. Bech32 addresses consist of a human readable part (HRP) concatenated
# with a data part, including a checksum, separated by a single character.
#
# Ruby reference implementation: https://github.com/sipa/bech32/tree/master/ref/ruby
module Bitcoin::Bech32

  SEPARATOR = '1'

  CHARSET = %w(q p z r y 9 x 8 g f 2 t v d w 0 s 3 j n 5 4 k h c e 6 m u a 7 l)

  class << self

    # Encode Bech32 string
    def encode(hrp, data)
      checksummed = data + create_checksum(hrp, data)
      hrp + SEPARATOR + checksummed.map{|i|CHARSET[i]}.join
    end

    # Decode a Bech32 string and determine hrp and data
    def decode(bech)
      # check invalid bytes
      return nil if bech.scrub('?').include?('?')
      # check uppercase/lowercase
      return nil if (bech.downcase != bech && bech.upcase != bech)
      bech.each_char{|c|return nil if c.ord < 33 || c.ord > 126}
      bech = bech.downcase
      # check data length
      pos = bech.rindex(SEPARATOR)
      return nil if pos.nil? || pos < 1 || pos + 7 > bech.length || bech.length > 90
      # check valid charset
      bech[pos+1..-1].each_char{|c|return nil unless CHARSET.include?(c)}
      # split hrp and data
      hrp = bech[0..pos-1]
      data = bech[pos+1..-1].each_char.map{|c|CHARSET.index(c)}
      # check checksum
      return nil unless verify_checksum(hrp, data)
      [hrp, data[0..-7]]
    end

    # Compute the checksum values given hrp and data.
    def create_checksum(hrp, data)
      values = expand_hrp(hrp) + data
      polymod = polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
      (0..5).map{|i|(polymod >> 5 * (5 - i)) & 31}
    end

    # Verify a checksum given Bech32 string
    def verify_checksum(hrp, data)
      polymod(expand_hrp(hrp) + data) == 1
    end

    private

    # Expand the hrp into values for checksum computation.
    def expand_hrp(hrp)
      hrp.each_char.map{|c|c.ord >> 5} + [0] + hrp.each_char.map{|c|c.ord & 31}
    end

    # Compute Bech32 checksum
    def polymod(values)
      generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
      chk = 1
      values.each do |v|
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        (0..4).each{|i|chk ^= ((top >> i) & 1) == 0 ? 0 : generator[i]}
      end
      chk
    end
  end
end
