module Bitcoin
  # Ruby port of https://github.com/Blockstream/contracthashtool
  module ContractHash
    HMAC_DIGEST = OpenSSL::Digest.new('SHA256')
    EC_GROUP = OpenSSL::PKey::EC::Group.new('secp256k1')

    def self.hmac(pubkey, data)
      OpenSSL::HMAC.hexdigest(HMAC_DIGEST, pubkey, data)
    end

    # generate a contract address
    def self.generate(redeem_script_hex, payee_address_or_ascii, nonce_hex = nil)
      redeem_script = Bitcoin::Script.new([redeem_script_hex].pack('H*'))
      raise 'only multisig redeem scripts are currently supported' unless redeem_script.is_multisig?
      nonce_hex, data = compute_data(payee_address_or_ascii, nonce_hex)

      derived_keys = []
      redeem_script.get_multisig_pubkeys.each do |pubkey|
        tweak = hmac(pubkey, data).to_i(16)
        raise 'order exceeded, pick a new nonce' if tweak >= EC_GROUP.order.to_i
        tweak = OpenSSL::BN.new(tweak.to_s)

        key = Bitcoin::Key.new(nil, pubkey.unpack('H*')[0])
        key = key.instance_variable_get(:@key)
        point = EC_GROUP.generator.mul(tweak).ec_add(key.public_key).to_bn.to_i
        raise 'infinity' if point == 1 / 0.0

        key = Bitcoin::Key.new(nil, point.to_s(16))
        key.instance_eval { @pubkey_compressed = true }
        derived_keys << key.pub
      end

      m = redeem_script.get_signatures_required
      p2sh_script, redeem_script = Bitcoin::Script.to_p2sh_multisig_script(m, *derived_keys)

      [nonce_hex, redeem_script.unpack('H*')[0], Bitcoin::Script.new(p2sh_script).get_p2sh_address]
    end

    # claim a contract
    def self.claim(private_key_wif, payee_address_or_ascii, nonce_hex)
      key = Bitcoin::Key.from_base58(private_key_wif)
      data = compute_data(payee_address_or_ascii, nonce_hex)[1]

      pubkey = [key.pub].pack('H*')
      tweak = hmac(pubkey, data).to_i(16)
      raise 'order exceeded, verify parameters' if tweak >= EC_GROUP.order.to_i

      derived_key = (tweak + key.priv.to_i(16)) % EC_GROUP.order.to_i
      raise 'zero' if derived_key.zero?

      Bitcoin::Key.new(derived_key.to_s(16))
    end

    # compute HMAC data
    def self.compute_data(address_or_ascii, nonce_hex)
      nonce = nonce_hex ? [nonce_hex].pack('H32') : SecureRandom.random_bytes(16)
      if Bitcoin.valid_address?(address_or_ascii)
        address_type = case Bitcoin.address_type(address_or_ascii)
                       when :hash160 then  'P2PH'
                       when :p2sh then     'P2SH'
                       else
                         raise "unsupported address type #{address_type}"
                       end
        contract_bytes = [Bitcoin.hash160_from_address(address_or_ascii)].pack('H*')
      else
        address_type = 'TEXT'
        contract_bytes = address_or_ascii
      end
      [nonce.unpack('H*')[0], address_type + nonce + contract_bytes]
    end
  end
end
