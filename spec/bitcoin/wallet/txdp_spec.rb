# encoding: ascii-8bit

require_relative '../spec_helper'
include Bitcoin
include Bitcoin::Wallet
include MiniTest

describe "Bitcoin::Wallet::TxDP" do

  before do
    Bitcoin.network = :testnet
  end

  it "should parse txdp" do
    txt = fixtures_file("txdp-1.txt")
    txdp = TxDP.parse(txt)
    txdp.id.should == "3fX59xPj"
    txdp.tx.size.should == 3
    txdp.tx.first.hash.should ==
      "2aa1938705066d0f9988923000ee75d5fc728b92b9739b71f94c139e5a729527"
    txdp.inputs.size.should == 2
  end

  it "should parse unsigned txdp" do
    txt = fixtures_file("txdp-2-unsigned.txt")
    txdp = TxDP.parse(txt)
    txdp.id.should == "7Q74Wkre"
    txdp.tx.size.should == 2
    txdp.inputs.size.should == 1
    txdp.inputs.first[1].should == nil
  end

  it "should parse signed txdp" do
    txt = fixtures_file("txdp-2-signed.txt")
    txdp = TxDP.parse(txt)
    txdp.id.should == "7Q74Wkre"
    txdp.tx.size.should == 2
    txdp.inputs.size.should == 1
    txdp.inputs.first[1].should ==[["mnheKkGdmw8d1fUV15XZbfmLR6AjQjVthy", "49304602210087bc1ff770c6cb3c7e47b9a3acb7dce678c16350f29acaa92e4ab231692256cf0221002da46fc1f39e132e726dea46a6e87e4278e85d36ccd393e39e931b89d55fc3a2014104955ec5646652d1b5bb14b2f867ef8879bcf224f1eab01072147fdfe0992440a234b36792937a23df736e8430613da6f0466bfc5505f2ad41b056131b7af13086"]]
  end

  it "should serialize unsigned txdp" do
    txt = fixtures_file("txdp-2-unsigned.txt")
    txdp = TxDP.parse(txt)
    txdp.serialize.should == txt.strip
  end

  it "should serialize signed txdp" do
    txt = fixtures_file("txdp-2-signed.txt")
    txdp = TxDP.parse(txt)
    txdp.serialize.should == txt.strip
  end

  it "should create txdp from tx" do
    tx1 = Bitcoin::P::Tx.from_json(fixtures_file("rawtx-05.json"))
    tx2 = Bitcoin::P::Tx.from_json(fixtures_file("rawtx-04.json"))
    sig = tx2.in[0].script_sig
    tx2.in[0].script_sig_length = 0
    tx2.in[0].script_sig = ""
    txdp = TxDP.new([tx2, tx1])
    txdp.id.should != nil
    txdp.inputs.size.should == 1
    txdp.inputs.first[0].should == 5e9
    txt = txdp.serialize

    txt.should =~ /--BEGIN-TRANSACTION-#{txdp.id}--/
    txt.should =~ /^_TXDIST_fabfb5da_#{txdp.id}_00cb$/
    txt.should =~ /^_TXINPUT_00_50.00000000$/
    txt.should =~ /--END-TRANSACTION-#{txdp.id}--/

    txdp.add_sig(0, tx1.out[0].value, "mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF", sig)
    txt = txdp.serialize
    txt.should =~ /^_SIG_mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF_00_0048$/
  end

end
