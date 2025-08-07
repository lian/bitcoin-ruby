require 'spec_helper'

module Bitcoin
  describe PKeyEC do
    let(:pkey) { PKeyEC }
    describe '.generate_key' do
      let(:generated_key) { Bitcoin::PKeyEC.generate_key }

      it 'generates a valid EC key' do
        expect(generated_key).to be_a(OpenSSL::PKey::EC)
      end

      it 'generates a key with private key component' do
        expect(generated_key.private_key?).to be true
      end

      it 'generates a key with public key component' do
        expect(generated_key.public_key?).to be true
      end

      it 'generates a key on the secp256k1 curve' do
        expect(generated_key.group.curve_name).to eq('secp256k1')
      end

      it 'generates unique keys on subsequent calls' do
        key1 = pkey.generate_key
        key2 = pkey.generate_key
        expect(key1.private_key.to_s(16)).not_to eq(key2.private_key.to_s(16))
      end
    end

    describe '#private_key' do
      let(:key) { Bitcoin::PKeyEC.new }

      it 'sets the private key' do
        key.private_key = OpenSSL::BN.new('0123456789abcdef', 16)
        expect(key.private_key.to_s(16)).to eq('0123456789ABCDEF')
      end

      it 'returns the public key' do
        key.private_key = OpenSSL::BN.new('0123456789abcdef', 16)
        expect(key.public_key_hex).to eq('041a1fd15fce078234aa292fc024178056bf006433c9b4bd208f59eb4c9efec95ba18af1fe46980989d3ff75bf9601121151ef46e2cfab8999408319ce8f3be725')
      end
    end
  end
end