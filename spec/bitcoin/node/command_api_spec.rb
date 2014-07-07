require_relative '../spec_helper.rb'

include Bitcoin
include Builder

class Array
  def stringify_keys
    map do |e|
      (e.is_a?(Array) || e.is_a?(Hash)) ? e.stringify_keys : e
    end
  end
end

class Hash
  def stringify_keys
    Hash[map do |k, v|
      v = v.stringify_keys  if v.is_a?(Hash) || v.is_a?(Array)
      [k.to_s, v]
    end]
  end
end

describe 'Node Command API' do

  TSLB_TIMEOUT = 3

  def test_command command, params = nil, response = nil, &block
    $responses = {}
    EM.run do
      @client = Bitcoin::Network::CommandClient.connect(*@config[:command]) do
        on_connected do
          request(command, params)
        end
        on_response do |cmd, data|
          $responses[cmd] = data
          EM.stop
        end
      end
    end

    result = $responses[command]

    return result  unless response || block

    if block
      block.call(result)
    else
      raise "ERROR: #{result} != #{response}"  unless result.should == response
    end
  end


  before do
    Bitcoin::Validation::Block::RULES.merge({
      syntax: [:hash, :tx_list, :bits, :max_timestamp, :coinbase, :coinbase_scriptsig, :transactions_syntax],
      context: [:prev_hash, :coinbase_value, :min_timestamp, :transactions_context]
    })

    Bitcoin.network = :spec
    @config = {
      listen: ["127.0.0.1", 38333],
      command: ["127.0.0.1", 38332],
      storage: "sequel::sqlite:/",
      dns: false,
      intervals: { queue: 0.01 },
      log: { network: :warn, storage: :warn },
    }

    @node = Bitcoin::Network::Node.new(@config)
    @pid = fork do
#      $stdout = StringIO.new
      SimpleCov.running = false if defined?(SimpleCov)
      @node.run
    end

    @genesis = P::Block.new("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000".htb)

    Bitcoin.network[:proof_of_work_limit] = Bitcoin.encode_compact_bits("ff"*32)
    @key = Bitcoin::Key.generate
    @block = create_block @genesis.hash, false, [], @key

    test_command "store_block", hex: @genesis.to_payload.hth
    sleep 0.1

    @id = 0
  end

  after do
    Process.kill("TERM", @pid)
  end

  it "should return error for unknown command" do
    test_command("foo", nil, {"error" => "unknown command: foo. send 'help' for help."})
  end

  # it "should return error for wrong parameters" do
  #   test_command("info", "foo", {"error" => "wrong number of arguments (1 for 0)"})
  # end

  it "should query tslb" do
    test_command("tslb") {|r| (0..TSLB_TIMEOUT).include?(r['tslb']).should == true }
  end

  it "should query info" do
    info = test_command "info"
    info.is_a?(Hash).should == true
    info["blocks"].should == { "depth" => 0, "peers" => "?", "sync" => false }
    info["addrs"].should == { "alive" => 0, "total" => 0 }
    info["connections"].should == {
      "established" => 0, "outgoing" => 0, "incoming" => 0, "connecting" => 0 }
    info["queue"].should == 0
    info["inv_queue"].should == 0
    info["inv_cache"].should == 0
    info["network"].should == "bitcoin"
    info["storage"].should == "sequel::sqlite:/"
    info["version"].should == 70001
    info["external_ip"].should == "127.0.0.1"
    info["uptime"].between?(0, 1).should == true
  end

  it "should query config" do
    test_command("config").should == JSON.load(@node.config.to_json)
  end

  # TODO
  it "should query connections" do
    test_command("connections").should == []
  end

  # TODO
  it "should connect" do
    test_command("connect", {host: "127.0.0.1", port: 1234})["state"].should == "connecting"
  end

  # TODO
  it "should disconnect" do
    test_command("disconnect", ["127.0.0.1:1234"])["state"].should == "disconnected"
  end

  it "should store block" do
    test_command("info")["blocks"].should == {"depth" => 0, "peers" => "?", "sync" => false}
    res = test_command("store_block", { hex: @block.to_payload.hth })
    res.should == { "queued" => @block.hash }
    sleep 0.1
    test_command("info")["blocks"]["depth"].should == 1
    test_command("info")["blocks"]["sync"].should == true
  end

  # TODO
  # it "should store tx" do
  #   @tx = @block.tx[1]
  #   res = test_command("store_tx", { hex: @tx.to_payload.htb })
  #   res.should == { "queued" => @tx.hash }
  # end

  describe :create_tx do

    before do
      @key2 = Key.generate
      test_command("store_block", hex: @block.to_payload.hth)
      sleep 0.1
    end

    it "should create transaction from given private keys" do
      res = test_command("create_tx", {
          keys: [ @key.to_base58 ], 
          recipients: [[@key2.addr, 10e8], [@key.addr, 40e8]]
        })
      tx = P::Tx.new(res["hex"].htb)
      tx.hash.should == res["hash"]
      tx.verify_input_signature(0, @block.tx[0]).should == true
    end

    it "should create unsigned transaction from given addresses" do
      res = test_command("create_tx", {
          keys: [ @key.addr ], 
          recipients: [[@key2.addr, 10e8], [@key.addr, 40e8]]
        })
      tx = P::Tx.new(res["hex"].htb)
      tx.hash.should == res["hash"]
      tx.in[0].script_sig.should == ""
      #-> { tx.verify_input_signature(0, @block.tx[0]) }.should.raise(TypeError)
      tx.verify_input_signature(0, @block.tx[0]).should == false

      res["missing_sigs"].each.with_index do |sig_data, idx|
        sig_hash, sig_addr = *sig_data
        sig_addr.should == @key.addr
        sig = @key.sign(sig_hash.htb)
        script_sig = Script.to_signature_pubkey_script(sig, @key.pub.htb)
        tx.in[idx].script_sig_length = script_sig.bytesize
        tx.in[idx].script_sig = script_sig
      end

      tx.verify_input_signature(0, @block.tx[0]).should == true
    end

    it "should create transaction from given pubkeys" do
      res = test_command("create_tx", {
          keys: [@key.pub], 
          recipients: [[@key2.addr, 10e8], [@key.addr, 40e8]]
        })
      tx = P::Tx.new(res["hex"].htb)
      tx.hash.should == res["hash"]
      #-> { tx.verify_input_signature(0, @block.tx[0]) }.should.raise(TypeError)
      tx.verify_input_signature(0, @block.tx[0]).should == false

      res["missing_sigs"].each.with_index do |sig_data, idx|
        sig_hash, sig_addr = *sig_data
        sig_addr.should == @key.addr
        sig = @key.sign(sig_hash.htb)
        script_sig = Script.to_signature_pubkey_script(sig, @key.pub.htb)
        tx.in[idx].script_sig_length = script_sig.bytesize
        tx.in[idx].script_sig = script_sig
      end

      tx.verify_input_signature(0, @block.tx[0]).should == true
    end

  end

  describe :assemble_tx do

    it "should assemble tx from unsigned tx structure, signatures and pubkeys" do
      tx = build_tx do |t|
        t.input do |i|
          i.prev_out @block.tx[0]
          i.prev_out_index 0
        end
        t.output {|o| o.value 50e8; o.script {|s| s.recipient @key.addr } }
      end
      sig = @key.sign(tx.in[0].sig_hash)
      test_command("store_block", hex: @block.to_payload.hth)
      sleep 0.1
      res = test_command("assemble_tx", {tx: tx.to_payload.hth, sig_pubs: [[sig.hth, @key.pub]]})
      tx = Bitcoin::P::Tx.new(res["hex"].htb)
      tx.hash.should == res["hash"]
      tx.verify_input_signature(0, @block.tx[0]).should == true
    end

  end

  describe :relay_tx do

    it "should handle decoding error" do
      res = test_command("relay_tx", hex: "foobar")
      res["error"].should == "Error decoding transaction."
    end

    it "should handle syntax error" do
      # create transaction with invalid output size
      block = create_block(@block.hash, false, [->(t) {
        create_tx(t, @block.tx[0], 0, [[22e14, @key]]) }], @key)
      tx = block.tx[1]

      error = test_command("relay_tx", hex: tx.to_payload.hth)
      error["error"].should == "Transaction syntax invalid."
      error["details"].should == ["output_values", [22e14, 21e14]]
    end

    it "should handle context error" do
      # create transaction with invalid input
      block = create_block(@block.hash, false, [->(t) {
        create_tx(t, @block.tx[0], 0, [[25e8, @key]]) }], @key)
      tx = block.tx[1]

      error = test_command("relay_tx", hex: tx.to_payload.hth)
      error["error"].should == "Transaction context invalid."
      error["details"].should == ["prev_out", [[@block.tx[0].hash, 0]]]
    end

    it "should relay transaction" do
      block = create_block(@block.hash, false, [->(t) {
        create_tx(t, @block.tx[0], 0, [[25e8, @key]]) }], @key)
      tx = block.tx[1]

      test_command("store_block", hex: @block.to_payload.hth)
      sleep 0.1
      res = test_command("relay_tx", hex: tx.to_payload.hth, send: 1, wait: 0)
      res["success"].should == true
      res["hash"].should == tx.hash
      res["propagation"].should == { "sent" => 1, "received" => 0, "percent" => 0.0 }
    end

  end

  describe :monitor do

    before do
      @client = TCPSocket.new(*@config[:command])

      def send method, params = nil, client = @client
        request = { id: @id += 1, method: method, params: params }
        client.write(request.to_json + "\x00")
        request.stringify_keys
      end

      def should_receive request, expected, client = @client
        expected = expected.stringify_keys  if expected.is_a?(Hash)
        begin
          Timeout.timeout(100) do
            buf = ""
            while b = client.read(1)
              break  if b == "\x00"
              buf << b
            end
            resp = JSON.load(buf)
            expected = request.merge(result: expected).stringify_keys
            expected.delete("params")
            raise "ERROR: #{resp} != #{expected}"  unless resp.should == expected
          end
        rescue Timeout::Error
          print " [TIMEOUT]"
          :timeout.should == nil
        end
      end

      def should_receive_block request, block, depth, client = @client
        expected = { hash: block.hash, hex: block.to_payload.hth, depth: depth }
        should_receive(request, expected, client)
      end

      def should_receive_tx request, tx, conf, client = @client
        expected = { hash: tx.hash, nhash: tx.nhash, hex: tx.to_payload.hth, conf: conf }
        should_receive(request, expected, client)
      end

      def should_receive_output request, tx, idx, conf, client = @client
        expected = { hash: tx.hash, nhash: tx.nhash, idx: idx,
          address: tx.out[idx].parsed_script.get_address, value: tx.out[idx].value, conf: conf }
        should_receive(request, expected, client)
      end

      def store_block block
        request = send("store_block", hex: block.to_payload.hth)
        should_receive(request, {"queued" => block.hash })
      end

    end

    describe :channels do

      it "should combine multiple channels" do
        should_receive r1 = send("monitor", channel: "block"), id: 0
        should_receive r2 = send("monitor", channel: "tx", conf: 1), id: 1
        store_block @block
        should_receive_block(r1, @block, 1)
        should_receive_tx(r2, @block.tx[0], 1)
      end

      it "should handle multiple clients" do
        @client2 = TCPSocket.new(*@config[:command])
        should_receive r1_1 = send("monitor", channel: "tx", conf: 1), id: 0
        r1_2 = send("monitor", { channel: "block" }, @client2)
        should_receive r1_2, { id: 0 }, @client2

        store_block @block

        should_receive_block(r1_2, @block, 1, @client2)
        should_receive_tx(r1_1, @block.tx[0], 1)

        block = create_block @block.hash, false
        store_block block

        should_receive_block(r1_2, block, 2, @client2)
        should_receive_tx(r1_1, block.tx[0], 1)

        r2_2 = send "monitor", { channel: "tx", conf: 1 }, @client2
        should_receive r2_2, { id: 1 }, @client2
        should_receive r2_1 = send("monitor", channel: "block"), id: 1

        block = create_block block.hash, false
        store_block block

        should_receive_block(r1_2, block, 3, @client2)
        should_receive_tx(r2_2, block.tx[0], 1, @client2)

        should_receive_tx(r1_1, block.tx[0], 1)

        # if something was wrong, we would now receive the last tx again

        should_receive_block(r2_1, block, 3)

        block = create_block block.hash, false
        store_block block

        should_receive_tx(r1_1, block.tx[0], 1)

        should_receive_block(r2_1, block, 4)
        should_receive_block(r1_2, block, 4, @client2)
        should_receive_tx(r2_2, block.tx[0], 1, @client2)
      end

    end

    describe :block do

      before do
        @request = send "monitor", channel: "block"
        
        should_receive(@request, id: 0)
        store_block @block
        should_receive_block(@request, @block, 1)
      end

      it "should monitor block" do
        @block = create_block @block.hash, false
        store_block @block
        should_receive_block(@request, @block, 2)
      end

      it "should unmonitor block" do
        @request = send "unmonitor", id: 0
        should_receive @request, id: 0
        store_block create_block(@block.hash, false)

        test_command("tslb") {|r| (0..TSLB_TIMEOUT).include?(r['tslb']).should == true }
      end

      it "should not monitor side or orphan blocks" do
        @side = create_block @genesis.hash, false
        store_block @side

        @orphan = create_block "00" * 32, false
        store_block @orphan

        # should not send side or orphan block only the next main block
        @block = create_block @block.hash, false
        store_block @block

        should_receive_block(@request, @block, 2)
      end

      it "should received missed blocks when last block hash is given" do
        @client = TCPSocket.new(*@config[:command])
        blocks = [@block]
        3.times do
          blocks << create_block(blocks.last.hash, false)
          store_block blocks.last
        end
        sleep 0.1

        r = send "monitor", channel: "block", last: blocks[1].hash

        should_receive_block(r, blocks[1], 2)
        should_receive_block(r, blocks[2], 3)
        should_receive_block(r, blocks[3], 4)
      end

    end

    describe :reorg do

      before do
        @request = send "monitor", channel: "reorg"
        should_receive @request, id: 0
        store_block @block
      end

      it "should monitor reorg" do
        @block1 = create_block @genesis.hash, false
        store_block @block1
        @block2 = create_block @block1.hash, false
        store_block @block2
        should_receive @request, { new_main: [ @block1.hash ], new_side: [ @block.hash ] }
      end

      it "should unmonitor reorg" do
        r = send "unmonitor", id: 0
        should_receive r, id: 0
        @block1 = create_block @genesis.hash, false
        store_block @block1
        @block2 = create_block @block1.hash, false
        store_block @block2

        test_command("tslb") {|r| (0..TSLB_TIMEOUT).include?(r['tslb']).should == true }
      end

    end

    describe :tx do


      it "should monitor unconfirmed tx" do
        r1 = send "monitor", channel: "tx"
        should_receive r1, id: 0
        tx = @block.tx[0]
        r2 = send "store_tx", hex: tx.to_payload.hth
        should_receive r2, { "queued" => tx.hash }

        should_receive_tx(r1, tx, 0)
      end

      it "should unmonitor tx" do
        r1 = send "monitor", channel: "tx"
        should_receive r1, id: 0

        r2 = send "unmonitor", id: 0
        should_receive r2, id: 0

        tx = @block.tx[0]
        r3 = send "store_tx", hex: tx.to_payload.hth
        should_receive r3, { "queued" => tx.hash }

        test_command("tslb") {|r| (0..TSLB_TIMEOUT).include?(r['tslb']).should == true }
      end

      it "should monitor confirmed tx" do
        r = send "monitor", channel: "tx", conf: 1
        should_receive r, id: 0
        store_block @block

        should_receive_tx(r, @block.tx[0], 1)
      end

      it "should monitor tx for given confirmation level" do
        r = send "monitor", channel: "tx", conf: 3
        should_receive r, id: 0

        @tx = @block.tx[0]
        store_block @block
        @block = create_block @block.hash, false
        store_block @block

        should_receive_tx(r, @genesis.tx[0], 3)

        @block = create_block @block.hash, false
        store_block @block

        should_receive_tx(r, @tx, 3)
      end

      it "should receive missed txs when last txhash is given" do
        @client = TCPSocket.new(*@config[:command])
        blocks = [@block]; store_block @block
        3.times do
          blocks << create_block(blocks.last.hash, false)
          store_block blocks.last
        end
        sleep 0.1

        r = send "monitor", channel: "tx", conf: 1, last: blocks[0].tx[0].hash

        should_receive_tx(r, blocks[1].tx[0], 3)
        should_receive_tx(r, blocks[2].tx[0], 2)
        should_receive_tx(r, blocks[3].tx[0], 1)

        should_receive r, id: 0
      end


      it "should filter txs for given addresses" do
        @key2 = Bitcoin::Key.generate
        block = create_block(@block.hash, false, [->(t) {
              create_tx(t, @block.tx[0], 0, [[50e8, @key2]]) }], @key)
        @addr = @block.tx[0].out[0].parsed_script.get_address
        r = send "monitor", channel: "tx", conf: 1, addresses: [ @key2.addr ]
        should_receive r, id: 0
        store_block @block
        store_block block
        should_receive_tx(r, block.tx[1], 1)
      end

    end

    describe :output do

      before do
        @tx = @block.tx[0]; @out = @tx.out[0]
      end

      it "should monitor unconfirmed outputs" do
        r1 = send "monitor", channel: "output"
        should_receive r1, id: 0
        tx = @block.tx[0]
        r2 = send "store_tx", hex: tx.to_payload.hth
        should_receive r2, { "queued" => tx.hash }
        should_receive_output(r1, tx, 0, 0)
      end

      it "should unmonitor outputs" do
        should_receive send("monitor", channel: "output"), id: 0
        should_receive send("unmonitor", id: 0), id: 0

        tx = @block.tx[0]
        r2 = send "store_tx", hex: tx.to_payload.hth
        should_receive r2, { "queued" => tx.hash }

        test_command("tslb") {|r| (0..TSLB_TIMEOUT).include?(r['tslb']).should == true }
      end

      it "should monitor confirmed output" do
        r = send "monitor", channel: "output", conf: 1
        should_receive r, id: 0
        store_block @block
        should_receive_output(r, @tx, 0, 1)
      end

      it "should monitor output for given confirmation level" do
        r = send "monitor", channel: "output", conf: 3
        should_receive r, id: 0
        store_block @block
        @block = create_block @block.hash, false
        store_block @block
        tx = @genesis.tx[0]; out = tx.out[0]
        should_receive_output(r, tx, 0, 3)

        @block = create_block @block.hash, false
        store_block @block
        should_receive_output(r, @tx, 0, 3)
      end

      it "should receive missed outputs when last txhash:idx is given" do
        @key = Bitcoin::Key.generate
        @client = TCPSocket.new(*@config[:command])
        blocks = [@block]; store_block @block
        3.times do
          blocks << create_block(blocks.last.hash, false, [], @key)
          store_block blocks.last
        end
        sleep 0.1

        r = send "monitor", channel: "output", conf: 1, last: "#{blocks[0].tx[0].hash}:0"

        should_receive_output(r, blocks[1].tx[0], 0, 3)
        should_receive_output(r, blocks[2].tx[0], 0, 2)
        should_receive_output(r, blocks[3].tx[0], 0, 1)

        should_receive r, id: 0
      end

      it "should filter outputs for given addresses" do
        @key2 = Bitcoin::Key.generate
        block = create_block(@block.hash, false, [->(t) {
              create_tx(t, @block.tx[0], 0, [[50e8, @key2]]) }], @key)

        r = send "monitor", channel: "output", conf: 1, addresses: [ @key2.addr ]
        should_receive r, id: 0
        store_block @block
        store_block block
        should_receive_output(r, block.tx[1], 0, 1)
      end

      it "should add filter address to output monitor params" do
        @key2 = Bitcoin::Key.generate
        block = create_block(@block.hash, false, [->(t) {
              create_tx(t, @block.tx[0], 0, [[50e8, @key2]]) }], @key)

        r1 = send "monitor", channel: "output", conf: 1, addresses: [  ]
        should_receive r1, id: 0

        r2 = send "filter_monitor_output", id: 0, address: @key2.addr
        should_receive r2, id: 0

        store_block @block
        store_block block
        should_receive_output(r1, block.tx[1], 0, 1)
      end

    end

  end

end
