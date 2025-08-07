module Bitcoin
  class PKeyEC #< OpenSSL::PKey::EC

    CURVE = 'secp256k1'

    attr_reader :group, :private_key, :public_key


    def private_key_hex; private_key.to_hex.rjust(64, '0'); end
    def public_key_hex;  public_key.to_hex.rjust(130, '0'); end

    def initialize
      @group = OpenSSL::PKey::EC::Group.new(CURVE)
    end

    def self.generate_key
      OpenSSL::PKey::EC.generate(CURVE)
    end

    def public_key=(public_key_bn)
      @public_key = public_key_bn
    end

    def private_key=(private_key_bn)
      @public_key = restore_public_key(private_key_bn)
      asn1 = OpenSSL::ASN1::Sequence(
        [
          OpenSSL::ASN1::Integer.new(1),
          OpenSSL::ASN1::OctetString(private_key_bn.to_s(2)),
          OpenSSL::ASN1::ObjectId(CURVE, 0, :EXPLICIT),
          OpenSSL::ASN1::BitString(@public_key.to_octet_string(:uncompressed), 1, :EXPLICIT)
        ]
      )
      @pk = OpenSSL::PKey::EC.new(asn1.to_der)
      @private_key = @pk.private_key
    end

    def dsa_sign_asn1(data)
      @pk.dsa_sign_asn1(data)
    end

    def dsa_verify_asn1(data, signature)
      initialize_from_public_key unless @pk
      @pk.dsa_verify_asn1(data, signature)
    end

    def initialize_from_public_key
      asn1 = OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::Sequence.new([
                                        OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
                                        OpenSSL::ASN1::ObjectId.new(@group.curve_name)
                                      ]),
          OpenSSL::ASN1::BitString.new(@public_key.to_octet_string(:uncompressed))
        ]
      )
      @pk = OpenSSL::PKey::EC.new(asn1.to_der)
    end

    private

    def restore_public_key(private_bn)
      public_bn = group.generator.mul(private_bn).to_bn
      public_bn = OpenSSL::PKey::EC::Point.new(@group, public_bn)
    end
  end
end