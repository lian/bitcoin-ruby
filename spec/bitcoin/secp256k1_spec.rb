# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'bitcoin'

describe 'libsecp256k1' do

  it 'generate key pair' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair(compressed = true)
    [priv, pub].map(&:bytesize).should == [32, 33]
    ["\x03", "\x02"].include?(pub[0]).should == true

    priv, pub = Bitcoin::Secp256k1.generate_key_pair(compressed = false)
    [priv, pub].map(&:bytesize).should == [32, 65]
    ["\x04"].include?(pub[0]).should == true
  end

  it 'sign and verify' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair
    signature = Bitcoin::Secp256k1.sign("derp", priv)
    Bitcoin::Secp256k1.verify("derp", signature, pub).should == true
  end

  it 'sign compact and recover' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair(compressed=true)
    signature = Bitcoin::Secp256k1.sign_compact("derp", priv, compressed=true)
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

  it 'deterministic signature using rfc6979' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair
    first  = Bitcoin::Secp256k1.sign("derp", priv)
    second = Bitcoin::Secp256k1.sign("derp", priv)
    first.should == second
  end

end
