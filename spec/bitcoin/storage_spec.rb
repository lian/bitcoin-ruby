require_relative 'spec_helper'

[
#  { :name => :dummy },
  { :name => :sequel, :db => 'sqlite:/' }, # in memory
#  { :name => :sequel, :db => 'sqlite:///tmp/bitcoin_test.db' },
#  { :name => :sequel, :db => 'postgres://localhost/bitcoin_test' },
].each do |configuration|
  describe "Bitcoin::Storage::Backends::#{configuration[:name].capitalize}Store" do

    before do
      Bitcoin::network = :testnet
      Bitcoin::Storage.log.level = 3
      @store = Bitcoin::Storage.send(configuration[:name], configuration)
      @store.reset

      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_0.bin')))
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_1.bin')))
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_2.bin')))
      @store.store_block(Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_3.bin')))

      @store.store_tx(Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-01.bin')))
      @store.store_tx(Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-02.bin')))


      @blk = Bitcoin::Protocol::Block.new(fixtures_file('testnet/block_4.bin'))
      @tx = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-03.bin'))
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
        .should == @store.get_block("0000000098932356a236718829dd9e3eb0f9143317ab921333b1a203de336de4")
    end

    it "should get locator" do
      @store.get_locator.should == [
        "0000000098932356a236718829dd9e3eb0f9143317ab921333b1a203de336de4",
        "000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f",
        "000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604",
        "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"]
    end

    it "should not store if there is no prev block" do
      @store.reset
      @store.store_block(@blk).should == [0, 2]
      @store.get_depth.should == -1
    end

    it "should check whether block is already stored" do
      @store.has_block(@blk.hash).should == false
      @store.store_block(@blk)
      @store.has_block(@blk.hash).should == true
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

    it "should not get block" do
      @store.get_block("nonexistant").should == nil
    end

    it "should get block depth" do
      @store.get_block("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008")
        .depth.should == 0
      @store.get_block("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604")
        .depth.should == 1
      @store.get_block("000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f")
        .depth.should == 2
    end

    it "should get prev block" do
      @store.get_block("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008")
        .get_prev_block.should == nil
      @store.get_block("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604")
        .get_prev_block.should == 
        @store.get_block("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008")
    end

    it "should get next block" do
      @store.get_block("0000000098932356a236718829dd9e3eb0f9143317ab921333b1a203de336de4")
        .get_next_block.should == nil
      @store.get_block("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008")
        .get_next_block.should == 
        @store.get_block("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604")
    end

    it "should get block for tx" do
      @store.store_block(@blk)
      @store.get_block_by_tx(@blk.tx[0].hash).should == @blk
    end

    it "should store tx" do
      @store.store_tx(@tx).should != false
    end

    it "should not store tx if already stored and return existing id" do
      id = @store.store_tx(@tx)
      @store.store_tx(@tx).should == id
    end

    it "should check if tx is already stored" do
      @store.has_tx(@tx.hash).should == false
      @store.store_tx(@tx)
      @store.has_tx(@tx.hash).should == true
    end

    it "should store hash160 for txout" do
      @store.store_tx(@tx)
      @store.get_tx(@tx.hash).out[0].hash160
        .should == "3129d7051d509424d23d533fa2d5258977e822e3"
    end

    it "should get tx" do
      @store.store_tx(@tx)
      @store.get_tx(@tx.hash).should == @tx
    end

    it "should not get tx" do
      @store.get_tx("nonexistant").should == nil
    end


    it "should get txouts for pk script" do
      @store.store_block(@blk)
      script = @blk.tx[0].out[0].pk_script
      @store.get_txouts_for_pk_script(script)
        .should == [@blk.tx[0].out[0]]
    end

    it "should get block for tx" do
      @store.store_block(@blk)
      tx = @blk.tx[0]
      @store.get_tx(tx.hash).get_block.should == @blk
    end

    it "should get tx for txin" do
      @store.store_tx(@tx)
      @store.get_tx(@tx.hash).in[0].get_tx.should == @tx
    end

    it "should get prev out for txin" do
      tx = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.bin'))
      outpoint_tx = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9.bin'))
      @store.store_tx(outpoint_tx)
      @store.store_tx(tx)

      @store.get_tx(tx.hash).in[0].get_prev_out.should == outpoint_tx.out[0]
    end

    it "should get tx for txout" do
      @store.store_tx(@tx)
      @store.get_tx(@tx.hash).out[0].get_tx.should == @tx
    end

    it "should get next in for txin" do
      tx = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.bin'))
      outpoint_tx = Bitcoin::Protocol::Tx.new(fixtures_file('rawtx-0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9.bin'))
      @store.store_tx(outpoint_tx)
      @store.store_tx(tx)

      @store.get_tx(outpoint_tx.hash).out[0].get_next_in.should == tx.in[0]
    end

    it "should get txouts for hash160" do
      @store.store_tx(@tx)
      @store.get_txouts_for_hash160("3129d7051d509424d23d533fa2d5258977e822e3", true)
        .should == [@tx.out[0]]
    end

    it "should get txouts for address" do
      @store.store_tx(@tx)
      @store.get_txouts_for_address("mjzuXYR2fncbPzn9nR5Ee5gBgYk9UQx36x", true)
        .should == [@tx.out[0]]
    end

    it "should get balance for address" do
      @store.store_tx(@tx)
      @store.get_balance("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").should == 5000000000
      @store.get_balance("4580f1b3632948202655fd555fdaaf9b9ef5ac0d").should == 0
    end

    it "should store multisig tx and index hash160's" do
      (true.should==true) && next  if @store.class == Bitcoin::Storage::Backends::DummyStore
      *keys = Bitcoin::Key.generate, Bitcoin::Key.generate
      pk_script = Bitcoin::Script.to_multisig_script(1, keys[0].pub, keys[1].pub)
      txout = Bitcoin::Protocol::TxOut.new(1000, pk_script)
      @store.store_txout(0, txout, 0)
      keys.each do |key|
        hash160 = Bitcoin.hash160(key.pub)
        txouts = @store.get_txouts_for_hash160(hash160, true)
        txouts.size.should == 1
        txouts[0].pk_script.should == txout.pk_script
      end
    end

    it "should index output script type" do
      @store.store_tx(@tx)
      @store.get_tx(@tx.hash).out.first.type.should == :hash160
    end

  end
end
