# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'bitcoin'

describe 'libsecp256k1' do

  it 'sign and verify' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair
    signature = Bitcoin::Secp256k1.sign("derp", priv)
    Bitcoin::Secp256k1.verify("derp", signature, pub).should == true
  end

  it 'sign compact and recover' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair
    signature = Bitcoin::Secp256k1.sign_compact("derp", priv)
    signature.bytesize.should == 65
    pub2 = Bitcoin::Secp256k1.recover_compact("derp", signature)
    pub2.bytesize.should == 33
    pub2.should == pub

    # uncompressed
    priv, pub = Bitcoin::Secp256k1.generate_key_pair(compressed=false)
    signature = Bitcoin::Secp256k1.sign_compact("derp", priv, compressed=false)
    signature.bytesize.should == 65
    pub2 = Bitcoin::Secp256k1.recover_compact("derp", signature)
    pub2.bytesize.should == 65
    pub2.should == pub
  end

end
