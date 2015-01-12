# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'bitcoin'


describe 'Bitcoin FFI OpenSSL Helpers' do

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
