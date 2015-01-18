# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'bitcoin'


describe 'Bitcoin FFI OpenSSL Helpers' do
  it 'should convert high-S DER signatures to low-S equivalents' do
    Bitcoin.network = 'testnet'

    tx_in = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-testnet-6f0bbdd4e71a8af4305018d738184df32dbb6f27284fdebd5b56d16947f7c181.bin') )
    tx_out = Bitcoin::Protocol::Tx.new( fixtures_file('rawtx-testnet-a7c9b06e275e8674cc19a5f7d3e557c72c6d93576e635b33212dbe08ab7cdb60.bin') )
    original_hash = tx_out.hash
    tx_out.verify_input_signature(0, tx_in).should == true
    script_sig = Bitcoin::Script.new(tx_out.in[0].script_sig)
    sig = script_sig.chunks[0]
    pubkey = script_sig.chunks[1]
    Bitcoin::Script::is_low_der_signature?(sig).should == false

    sig = Bitcoin::OpenSSL_EC.signature_to_low_s(sig)
    Bitcoin::Script::is_low_der_signature?(sig).should == true

    tx_out.in[0].script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, pubkey)
    tx_out.verify_input_signature(0, tx_in).should == true

    # Repack the transaction to force hash update
    tx_out = Bitcoin::Protocol::Tx.new( tx_out.to_payload )
    original_hash.should != tx_out.hash

    Bitcoin.network = 'bitcoin'
  end

  it 'Bitcoin::OpenSSL_EC.repack_der_signature' do
    s = "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"
    ns = Bitcoin::OpenSSL_EC.repack_der_signature([s].pack("H*")).unpack("H*")[0]
    ns.should == s

    [
      "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860",
      "304402204e45e16932",
      "304402204",
      "3044",
    ].all?{|s| Bitcoin::OpenSSL_EC.repack_der_signature([s].pack("H*")) == false }.should == true
  end
end
