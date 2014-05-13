require 'openssl'

module Litecoin
  module Scrypt

    def scrypt_1024_1_1_256_sp(input, scratchpad=[])
      b = pbkdf2_sha256(input, input, 1, 128)
      x = b.unpack("V*")
      v = scratchpad

      1024.times{|i|
        v[(i*32)...((i*32)+32)] = x.dup
        xor_salsa8(x, x, 0, 16)
        xor_salsa8(x, x, 16, 0)
      }

      1024.times{|i|
        j = 32 * (x[16] & 1023)
        32.times{|k| x[k] ^= v[j+k] }
        xor_salsa8(x, x, 0, 16)
        xor_salsa8(x, x, 16, 0)
      }

      pbkdf2_sha256(input, x.pack("V*"), 1, 32)
    end

    def pbkdf2_sha256(pass, salt, c=1, dk_len=128)
      raise "pbkdf2_sha256: wrong length." if pass.bytesize != 80 or ![80,128].include?(salt.bytesize)
      raise "pbkdf2_sha256: wrong dk length." if ![128,32].include?(dk_len)
      OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, iter=c, dk_len, OpenSSL::Digest::SHA256.new)
    end

    def rotl(a, b)
      a &= 0xffffffff; ((a << b) | (a >> (32 - b))) & 0xffffffff
    end

    def xor_salsa8(a, b, a_offset, b_offset)
      x = 16.times.map{|n| a[a_offset+n] ^= b[b_offset+n] }

      4.times{
        [
          [4, 0, 12, 7], [9, 5, 1, 7],  [14, 10, 6, 7], [3, 15, 11, 7],
          [8, 4, 0, 9], [13, 9, 5, 9],  [2, 14, 10, 9], [7, 3, 15, 9],
          [12, 8, 4, 13], [1, 13, 9, 13],  [6, 2, 14, 13], [11, 7, 3, 13],
          [0, 12, 8, 18], [5, 1, 13, 18],  [10, 6, 2, 18], [15, 11, 7, 18],

          [1, 0, 3, 7], [6, 5, 4, 7],  [11, 10, 9, 7], [12, 15, 14, 7],
          [2, 1, 0, 9], [7, 6, 5, 9],  [8, 11, 10, 9], [13, 12, 15, 9],
          [3, 2, 1, 13], [4, 7, 6, 13],  [9, 8, 11, 13], [14, 13, 12, 13],
          [0, 3, 2, 18], [5, 4, 7, 18],  [10, 9, 8, 18], [15, 14, 13, 18]
        ].each{|i|
          x[ i[0] ] ^= rotl(x[ i[1] ] + x[ i[2] ], i[3])
        }
      }

      16.times{|n| a[a_offset+n] = (a[a_offset+n] + x[n]) & 0xffffffff }
      true
    end

    extend self
  end
end


if $0 == __FILE__
  secret_hex = "020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659"
  secret_bytes = [secret_hex].pack("H*")
 
  begin
    require "scrypt"
    hash = SCrypt::Engine.__sc_crypt(secret_bytes, secret_bytes, 1024, 1, 1, 32)
    p hash.reverse.unpack("H*")[0] == "00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806"
  rescue LoadError
    puts "scrypt gem not found, using native scrypt"
    p Litecoin::Scrypt.scrypt_1024_1_1_256_sp(secret_bytes).reverse.unpack("H*")[0] == "00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806"
  end

  require 'benchmark'
  Benchmark.bmbm{|x|
    x.report("v1"){ SCrypt::Engine.__sc_crypt(secret_bytes, secret_bytes, 1024, 1, 1, 32).reverse.unpack("H*") rescue nil }
    x.report("v2"){ Litecoin::Scrypt.scrypt_1024_1_1_256_sp(secret_bytes).reverse.unpack("H*")[0] }
  }
end
