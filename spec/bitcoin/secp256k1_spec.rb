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

  it 'generate key' do
    key = Bitcoin::Secp256k1.generate_key(compressed = true)
    key.compressed.should == true

    key = Bitcoin::Secp256k1.generate_key(compressed = false)
    key.compressed.should == false
  end

  it 'sign and verify' do
    priv, pub = Bitcoin::Secp256k1.generate_key_pair
    signature = Bitcoin::Secp256k1.sign("derp", priv)
    Bitcoin::Secp256k1.verify("derp", signature, pub).should == true
    Bitcoin::Secp256k1.verify("DERP", signature, pub).should == true
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

    priv, pub = Bitcoin::Secp256k1.generate_key_pair
    second = Bitcoin::Secp256k1.sign("derp", priv)
    first.should != second
  end

  it 'openssl vs Secp256k1' do
    k = Bitcoin::Key.new("82a0c421a0f67c7a88a329b2c15f2849aa1c8cfa9c9a6513f056f80ee8eaacc4", nil, compresed=false); k.pub
    k.pub.should == "0490b0854581a291b83c1945775f156da22445df99e445581321ac3aa62535ff369334316dfd157acc7bb2e4d3eb85951f6d1b7f62f6f60a09e0dbd5c87d3ffae9"

    message = "hello world"
    priv = [k.priv].pack("H*")

    sig1 = Bitcoin::OpenSSL_EC.sign_compact(message, priv, nil, compressed=false)
    sig2 = Bitcoin::Secp256k1.sign_compact(message, priv, compressed=false)

    Bitcoin::OpenSSL_EC.recover_compact(message, sig1).should == k.pub
    Bitcoin::Secp256k1.recover_compact(message, sig1).unpack("H*")[0].should == k.pub

    Bitcoin::OpenSSL_EC.recover_compact(message, sig2).should == k.pub
    Bitcoin::Secp256k1.recover_compact(message, sig2).unpack("H*")[0] == k.pub
  end

end
