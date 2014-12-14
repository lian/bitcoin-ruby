# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'bitcoin/script'

include Bitcoin
include Bitcoin::Builder

describe 'Bitcoin::Namecoin' do

  describe :script do

    before do
      Bitcoin.network = :namecoin
      @name_new = Script.from_string("3045022023686b3584247c07f483de4048f3d5136c4faa2f961a6d1e487eb77437422b51022100b1ea62910f2dbb0533d32bd661e8a212d129057d3d71620572278895dbb5c7b501
          04b656d7be83e73344e298feba41b38c52ea50d4583ead0c947fd8019f75c906e0d810c5d167ee616c46d28d7cb5ca1d7a20a180470c9dad79524118bafe6cf569 1 820fa9c6d252d6773e4ef26a2feffa93f0237641 OP_2DROP OP_DUP OP_HASH160 eb86f8f23909e248d199192d8407881c3435a5db OP_EQUALVERIFY OP_CHECKSIG")
      @name_firstupdate = Script.from_string("3044022054e1557304c504498f8d40b961373d7401a4e4c1650518db8a9c3a49ee9add7e022061573b2837598c346b21c01969081a309c055d5da23b0ac7e139a6290f2f0a4b01
          04d2628245cdfc6ccf5a762d303ba8a10bd54d597cfdcbf0ac3823bae666a36bb744ed44a2384f42525e37b5b1150c5321718806c0f941904336588dd624f4ce93 2 642f626974636f696e a8c22832fb0d40e900 7b22696e666f223a7b22726567697374726172223a22687474703a2f2f72656769737465722e646f742d6269742e6f7267227d2c22656d61696c223a2022726567697374657240646f742d6269742e6f7267222c226e73223a5b226e73302e7765622d73776565742d7765622e6e6574222c226e73312e7765622d73776565742d7765622e6e6574225d2c226d6170223a7b22223a7b226e73223a5b226e73302e7765622d73776565742d7765622e6e6574222c226e73312e7765622d73776565742d7765622e6e6574225d7d7d7d OP_2DROP OP_2DROP OP_DUP OP_HASH160 f3f4aee9d80da759a4a3547cf6aa95c09881decb OP_EQUALVERIFY OP_CHECKSIG")
      @name_update = Script.from_string("304402206a8598a87aadd697732d0a187220023e2b54e542e144d0dee67660c8ca3d66f4022000de36f02afb9162f2d27e947d452d4e28baadfdb21637db2b1f252ad62d7fb201
          04b61d1529dbe912c84d0de898e88ab8a9d9fa4a13e76e7b60419dd3bd2b72021842bbf0f5eba1001d55f0c6f2c255289bedbe843d0164b545bbc056f150b4c3f2 3 642f626974636f696e 7b22696e666f223a7b22726567697374726172223a22687474703a2f2f72656769737465722e646f742d6269742e6f7267227d2c22656d61696c223a2022726567697374657240646f742d6269742e6f7267222c226e73223a5b226e73302e7765622d73776565742d7765622e6e6574222c226e73312e7765622d73776565742d7765622e6e6574225d2c226d6170223a7b22223a7b226e73223a5b226e73302e7765622d73776565742d7765622e6e6574222c226e73312e7765622d73776565742d7765622e6e6574225d7d7d7d OP_2DROP OP_DROP OP_DUP OP_HASH160 8f29c40b89ceda0b9176819e2bb5a15f592c6548 OP_EQUALVERIFY OP_CHECKSIG")
    end

    it 'should parse name_new script' do
      @name_new.is_name_new?.should == true
      @name_firstupdate.is_name_new?.should == false
      @name_update.is_name_new?.should == false
    end

    it 'should parse name_firstupdate script' do
      @name_new.is_name_firstupdate?.should == false
      @name_firstupdate.is_name_firstupdate?.should == true
      @name_update.is_name_firstupdate?.should == false
    end

    it 'should parse name_update script' do
      @name_new.is_name_update?.should == false
      @name_firstupdate.is_name_update?.should == false
      @name_update.is_name_update?.should == true
    end

    it 'should run scripts' do
      @name_new.run { true }.should == true
      @name_firstupdate.run { true }.should == true
      @name_update.run { true }.should == true
    end

    it 'should get name_hash' do
      @name_new.get_namecoin_hash.should == "820fa9c6d252d6773e4ef26a2feffa93f0237641"
    end

    it 'should get name' do
      @name_firstupdate.get_namecoin_name.should == "d/bitcoin"
      @name_update.get_namecoin_name.should == "d/bitcoin"
    end

    it 'should get value' do
      @name_firstupdate.get_namecoin_value.should == '{"info":{"registrar":"http://register.dot-bit.org"},"email": "register@dot-bit.org","ns":["ns0.web-sweet-web.net","ns1.web-sweet-web.net"],"map":{"":{"ns":["ns0.web-sweet-web.net","ns1.web-sweet-web.net"]}}}'
      @name_update.get_namecoin_value.should == @name_firstupdate.get_namecoin_value
    end

    def set_rand rand; @rand = rand; end

    it 'should create scripts' do
      key = Key.generate
      script = Script.to_name_new_script(self, "test/foo", key.addr)
      Script.new(script).to_string.should =~
        /^1 (.*?) OP_2DROP OP_DUP OP_HASH160 #{key.hash160} OP_EQUALVERIFY OP_CHECKSIG$/
      @rand.should != nil

      script = Script.to_name_firstupdate_script("test/foo", "1234", "testing", key.addr)
      Script.new(script).to_string.should ==
        "2 746573742f666f6f 1234 74657374696e67 OP_2DROP OP_2DROP " +
        "OP_DUP OP_HASH160 #{key.hash160} OP_EQUALVERIFY OP_CHECKSIG"

      script = Script.to_name_update_script("test/foo", "more testing", key.addr)
      Script.new(script).to_string.should ==
        "3 746573742f666f6f 6d6f72652074657374696e67 OP_2DROP OP_DROP " +
        "OP_DUP OP_HASH160 #{key.hash160} OP_EQUALVERIFY OP_CHECKSIG"
    end

  end

  [
   { :name => :utxo, :db => 'sqlite:/', utxo_cache: 0 },
   { :name => :sequel, :db => 'sqlite:/' },
  ].each do |configuration|

    describe "Namecoin (#{configuration[:name]} store)" do

      before do
        Bitcoin.network = :namecoin
        Bitcoin.network[:no_difficulty] = true
        class Bitcoin::Validation::Block; def min_timestamp; true; end; end
        Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("ff"*32)
        [:name_new, :name_firstupdate, :name_update].each {|type|
          Bitcoin::Storage::Backends::SequelStore::SCRIPT_TYPES << type }
        @store = Bitcoin::Storage.create_store(configuration[:name], configuration)
        @store.reset
        @store.log.level = :error
        @key = Bitcoin::Key.generate
        @block = create_block "00"*32, false, [], @key
        Bitcoin.network[:genesis_hash] = @block.hash
        @store.store_block(@block)
      end

      def set_rand r; @rand = r; end

      it "should store names" do
        # create name_new
        @block = create_block @block.hash, true, [->(t) {
          t.input {|i| i.prev_out @block.tx[0]; i.prev_out_index 0; i.signature_key @key }
          t.output {|o| o.value 50e8; o.script {|s| s.type(:name_new)
            s.recipient(self, "test", @key.addr) } } }], @key
        @store.db[:names][hash: Bitcoin.hash160(@rand + "test".hth)].should != nil

        # name_firstupdate should not be valid yet
        @block = create_block @block.hash, true, [->(t) {
          t.input {|i| i.prev_out @block.tx[0]; i.prev_out_index 0; i.signature_key @key }
          t.output {|o| o.value 50e8; o.script {|s| s.type(:name_firstupdate)
            s.recipient("test", @rand, "testvalue", @key.addr) } } }], @key
        @store.name_show("test").should == nil

        # create enough blocks for name_new to become valid
        Namecoin::FIRSTUPDATE_LIMIT.times {
          @block = create_block @block.hash, true, [], @key }

        # name_firstupdate should be valid now
        @block = create_block @block.hash, true, [->(t) {
          t.input {|i| i.prev_out @block.tx[0]; i.prev_out_index 0; i.signature_key @key }
          t.output {|o| o.value 50e8; o.script {|s|; s.type(:name_firstupdate)
            s.recipient("test", @rand, "testvalue", @key.addr) } } }], @key

        name = @store.name_show("test")
        name.get_address.should == @key.addr
        name.name.should == "test"
        name.value.should == "testvalue"
        name.hash.should == Bitcoin.hash160(@rand + "test".hth)

        # create name_update
        @new_key = Bitcoin::Key.generate
        @block = create_block @block.hash, true, [->(t) {
          t.input {|i| i.prev_out @block.tx[0]; i.prev_out_index 0; i.signature_key @key}
            t.output {|o|o.value 50e8; o.script {|s| s.type(:name_update)
              s.recipient("test", "testupdate", @new_key.addr) } } }], @new_key

        name = @store.name_show("test")
        name.get_address.should == @new_key.addr
        name.value.should == "testupdate"

        h = @store.name_history("test")
        h.size.should == 2
        h[0].value.should == "testvalue"
        h[0].get_address.should == @key.addr
        h[1].value.should == "testupdate"
        h[1].get_address.should == @new_key.addr
      end

      it "should expire names" do
        @block = create_block @block.hash, true, [->(t) {
          t.input {|i| i.prev_out @block.tx[0]; i.prev_out_index 0; i.signature_key @key }
          t.output {|o| o.value 50e8; o.script {|s| s.type(:name_new)
            s.recipient(self, "test", @key.addr) } } }], @key
        @store.db[:names][hash: Bitcoin.hash160(@rand + "test".hth)].should != nil

        # create enough blocks for name_new to become valid
        Namecoin::FIRSTUPDATE_LIMIT.times {
          @block = create_block @block.hash, true, [], @key }

        # name_firstupdate should be valid now
        @block = create_block @block.hash, true, [->(t) {
          t.input {|i| i.prev_out @block.tx[0]; i.prev_out_index 0; i.signature_key @key }
          t.output {|o| o.value 50e8; o.script {|s|; s.type(:name_firstupdate)
            s.recipient("test", @rand, "testvalue", @key.addr) } } }], @key

        @store.name_show("test").expires_in.should == Namecoin::EXPIRATION_DEPTH
        @block = create_block @block.hash, true, [], @key
        @store.name_show("test").expires_in.should == Namecoin::EXPIRATION_DEPTH - 1
      end

    end
  end
end
