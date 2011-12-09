require_relative 'spec_helper'


[
  { 'name' => 'Dummy' },
#  { 'name' => 'SequelStore', :db => 'postgres://localhost/bitcoin_test' },
#  { 'name' => 'Activerecord', 'adapter' => 'postgresql', 'database' => 'bitcoin_test' },
].each do |configuration|

  describe "Bitcoin::Storage::Backends::#{configuration['name']}" do

    before do
      Bitcoin::network = :testnet
      Bitcoin::Storage.log.level = 3
      
      klass = Bitcoin::Storage::Backends.const_get(configuration['name'])
      @store = klass.new(configuration)
      @store.reset
      
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin')))
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_1.bin')))
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_2.bin')))
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_3.bin')))
      
      @blk = Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_4.bin'))
      @tx = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-01.bin'))
    end

    it "should get depth" do
      @store.get_depth.should == 3
    end

    it "should report depth as -1 if store is empty" do
      @store.reset
      @store.get_depth.should == -1
    end
    
    it "should get head" do
      @store.get_head
        .should == "0000000098932356a236718829dd9e3eb0f9143317ab921333b1a203de336de4"
    end

    it "should get locator" do
      @store.get_locator.should == [
         "0000000098932356a236718829dd9e3eb0f9143317ab921333b1a203de336de4",
         "000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f",
         "000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604",
         "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"]
    end
    
    # it "should get balance"
    
    it "should store block" do
      @store.store_block(@blk).should == 4
      @store.get_depth.should == 4
      @store.get_tx(@blk.tx[0].hash).should == @blk.tx[0]
    end
    
    it "should get block by depth" do
      @store.get_block_by_depth(0).to_hash.should == 
        Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin')).to_hash
      @store.get_block_by_depth(1).to_hash.should == 
        Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_1.bin')).to_hash
      @store.get_block_by_depth(2).to_hash.should == 
        Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_2.bin')).to_hash
    end
    
    it "should get block by hash" do
      @store.get_block(
          "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008").to_hash
        .should == Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin')).to_hash
      
      @store.get_block(
          "000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604").to_hash
        .should == Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_1.bin')).to_hash
      @store.get_block(
          "000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f").to_hash
        .should == Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_2.bin')).to_hash
    end
    
    it "should get block depth" do
      @store.get_block_depth(
          "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008").should == 0
      @store.get_block_depth(
          "000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604").should == 1
      @store.get_block_depth(
          "000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f").should == 2
    end

    it "should store tx" do
      @store.store_tx(@tx).should != false
    end

    it "should get tx" do
      @store.store_tx(@tx)
      @store.get_tx(@tx.hash).should == @tx
    end

  end
end
