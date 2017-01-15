# encoding: ascii-8bit

module Bitcoin

  def self.hmac_sha512(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA512'), key, data)
  end

  def self.calc_fingerprint(pubkey_hex)
    Bitcoin.hash160(pubkey_hex).slice(0..7)
  end

  # Integers modulo the order of the curve(secp256k1)
  CURVE_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

  # BIP32 HD key
  class ExtKey

    attr_accessor :depth
    attr_accessor :fingerprint
    attr_accessor :number
    attr_accessor :chain_code
    attr_accessor :priv_key
    attr_reader :parent

    def initialize(parent = nil)
      @parent = parent
    end

    # generate master key from seed.
    def self.generate_master(seed)
      key = ExtKey.new
      key.depth = key.number = 0
      l = Bitcoin.hmac_sha512('Bitcoin seed', seed)
      left = OpenSSL::BN.from_hex(l[0..31].bth).to_i
      raise 'invalid key' if left >= CURVE_ORDER || left == 0
      key.priv_key = Bitcoin::Key.new(l[0..31].bth)
      key.fingerprint = Bitcoin.calc_fingerprint(key.priv_key.pub)
      key.chain_code = l[32..-1]
      key
    end

    # get ExtPubkey from priv_key
    def ext_pubkey
      k = parent ? ExtPubkey.new(parent.ext_pubkey) : ExtPubkey.new
      k.depth = depth
      k.number = number
      k.chain_code = chain_code
      k.fingerprint = fingerprint
      key = Bitcoin::Key.new(nil, priv_key.pub, compressed: true)
      k.pub_key = key.key.public_key
      k
    end

    # get parent's fingerprint
    def parent_fingerprint
      parent ? parent.fingerprint : '00000000'
    end

    # serialize key
    def to_payload
      Bitcoin.network[:extended_privkey_version].htb << [depth].pack('C') << parent_fingerprint.htb << [number].pack('N') << chain_code << [0x00].pack('C') << priv_key.priv.htb
    end

    # Base58 encoding
    def to_base58
      h = to_payload.bth
      hex = h + Bitcoin.checksum(h)
      Bitcoin.encode_base58(hex)
    end

    # derive new key
    def derive(number)
      new_key = ExtKey.new(self)
      new_key.depth = depth + 1
      new_key.number = number
      if number > (2**31 -1)
        data = [0x00].pack('C') << priv_key.priv.htb << [number].pack('N')
      else
        data = priv_key.pub.htb << [number].pack('N')
      end
      l = Bitcoin.hmac_sha512(chain_code, data)
      left = OpenSSL::BN.from_hex(l[0..31].bth).to_i
      raise 'invalid key' if left >= CURVE_ORDER
      child_priv = OpenSSL::BN.new((left + OpenSSL::BN.from_hex(priv_key.priv).to_i) % CURVE_ORDER)
      raise 'invalid key ' if child_priv.to_i >= CURVE_ORDER
      new_key.priv_key = Bitcoin::Key.new(child_priv.to_hex.rjust(64, '0'))
      new_key.chain_code = l[32..-1]
      new_key.fingerprint = Bitcoin.hash160(new_key.priv_key.pub).slice(0..7)
      new_key
    end

  end

  class ExtPubkey
    attr_accessor :depth
    attr_accessor :fingerprint
    attr_accessor :number
    attr_accessor :chain_code
    attr_accessor :pub_key
    attr_reader :parent

    def initialize(parent = nil)
      @parent = parent
    end

    # get parent's fingerprint
    def parent_fingerprint
      parent ? parent.fingerprint : '00000000'
    end

    def to_payload
      Bitcoin.network[:extended_pubkey_version].htb << [depth].pack('C') << parent_fingerprint.htb << [number].pack('N') << chain_code << to_hex.htb
    end

    def to_hex
      pub_key.group.point_conversion_form = :compressed
      pub_key.to_hex.rjust(66, '0')
    end

    def to_base58
      h = to_payload.bth
      hex = h + Bitcoin.checksum(h)
      Bitcoin.encode_base58(hex)
    end

    # derive child key
    def derive(number)
      new_key = ExtPubkey.new(self)
      new_key.depth = depth + 1
      new_key.number = number
      raise 'hardened key is not support' if number > (2**31 -1)
      data = to_hex.htb << [number].pack('N')
      l = Bitcoin.hmac_sha512(chain_code, data)
      left = OpenSSL::BN.from_hex(l[0..31].bth)
      raise 'invalid key' if left.to_i >= CURVE_ORDER
      new_key.pub_key = bitcoin_elliptic_curve.group.generator.mul(left).ec_add(pub_key)
      new_key.chain_code = l[32..-1]
      new_key.fingerprint = Bitcoin.hash160(new_key.to_hex).slice(0..7)
      new_key
    end
  end

end