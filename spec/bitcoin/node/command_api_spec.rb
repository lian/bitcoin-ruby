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

  def test_command command, params = [], response = nil, &block
    $responses = {}
    EM.run do
      @client = Bitcoin::Network::CommandClient.connect(*@config[:command]) do
        on_connected do
          request(command, *params)
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

    test_command "store_block", [@genesis.to_payload.hth]
    sleep 0.1

    @id = 0
  end

  after do
    Process.kill("TERM", @pid)
  end

  it "should return error for unknown command" do
    test_command("foo", nil, {"error" => "unknown command: foo. send 'help' for help."})
  end

  it "should return error for wrong parameters" do
    test_command("info", "foo", {"error" => "wrong number of arguments (1 for 0)"})
  end

  it "should query tslb" do
    test_command("tslb") do |res|
      res.keys.include?("tslb").should == true
      res["tslb"].should >= 0
      res["tslb"].should <= 1
    end
  end

  it "should query info" do
    info = test_command "info"
    info.is_a?(Hash).should == true
    info["blocks"].should == "0 (?)"
    info["addrs"].should == "0 (0)"
    info["connections"].should == "0 established (0 out, 0 in), 0 connecting"
    info["queue"].should == 0
    info["inv_queue"].should == 0
    info["inv_cache"].should == 0
    info["network"].should == "bitcoin"
    info["storage"].should == "sequel::sqlite:/"
    info["version"].should == 70001
    info["external_ip"].should == "127.0.0.1"
    info["uptime"].should =~ /00:00:00:0[0|1]/
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
    test_command("connect", ["127.0.0.1:1234"])["state"].should == "Connecting..."
  end

  # TODO
  it "should disconnect" do
    test_command("disconnect", ["127.0.0.1:1234"])["state"].should == "Disconnected"
  end

  it "should store block" do
    test_command("info")["blocks"].should == "0 (?)"
    res = test_command "store_block", [ @block.to_payload.hth ]
    res.should == { "queued" => [ "block", @block.hash ] }
    sleep 0.1
    test_command("info")["blocks"].should == "1 (?) sync"
  end

  describe :create_tx do

    before do
      @key2 = Key.generate
      test_command("store_block", [@block.to_payload.hth])
      sleep 0.1
    end

    it "should create transaction from given private keys" do
      res = test_command("create_tx", [[@key.to_base58], [[@key2.addr, 10e8], [@key.addr, 40e8]]])
      tx = P::Tx.new(res[0].htb)
      tx.is_a?(P::Tx).should == true
      tx.verify_input_signature(0, @block.tx[0]).should == true
    end

    it "should create transaction from given addresses" do
      res = test_command("create_tx", [[@key.addr], [[@key2.addr, 10e8], [@key.addr, 40e8]]])
      tx = P::Tx.new(res[0].htb)
      tx.is_a?(P::Tx).should == true
      tx.in[0].script_sig.should == ""
      #-> { tx.verify_input_signature(0, @block.tx[0]) }.should.raise(TypeError)
      tx.verify_input_signature(0, @block.tx[0]).should == false

      res[1].each.with_index do |sig_data, idx|
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
      res = test_command("create_tx", [[@key.pub], [[@key2.addr, 10e8], [@key.addr, 40e8]]])
      tx = P::Tx.new(res[0].htb)
      tx.is_a?(P::Tx).should == true
      #-> { tx.verify_input_signature(0, @block.tx[0]) }.should.raise(TypeError)
      tx.verify_input_signature(0, @block.tx[0]).should == false

      res[1].each.with_index do |sig_data, idx|
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
      test_command("store_block", [@block.to_payload.hth])
      sleep 0.1
      res = test_command("assemble_tx", [tx.to_payload.hth, [[sig.hth, @key.pub]]])
      tx = Bitcoin::P::Tx.new(res.htb)
      tx.verify_input_signature(0, @block.tx[0]).should == true
    end

  end

  describe :relay_tx do

    it "should handle decoding error" do
      res = test_command("relay_tx", ["foobar"])
      res["error"].should == "Error decoding transaction."
    end

    it "should handle syntax error" do
      # create transaction with invalid output size
      block = create_block(@block.hash, false, [->(t) {
        create_tx(t, @block.tx[0], 0, [[22e14, @key]]) }], @key)
      tx = block.tx[1]

      error = test_command("relay_tx", [tx.to_payload.hth])
      error["error"].should == "Transaction syntax invalid."
      error["details"].should == ["output_values", [22e14, 21e14]]
    end

    it "should handle context error" do
      # create transaction with invalid input
      block = create_block(@block.hash, false, [->(t) {
        create_tx(t, @block.tx[0], 0, [[25e8, @key]]) }], @key)
      tx = block.tx[1]

      error = test_command("relay_tx", [tx.to_payload.hth])
      error["error"].should == "Transaction context invalid."
      error["details"].should == ["prev_out", [[@block.tx[0].hash, 0]]]
    end

    it "should relay transaction" do
      block = create_block(@block.hash, false, [->(t) {
        create_tx(t, @block.tx[0], 0, [[25e8, @key]]) }], @key)
      tx = block.tx[1]

      test_command("store_block", [@block.to_payload.hth])
      sleep 0.1
      res = test_command("relay_tx", [tx.to_payload.hth, 1, 0])
      res["success"].should == true
      res["hash"].should == tx.hash
      res["propagation"].should == { "sent" => 1, "received" => 0, "percent" => 0.0 }
    end

  end

  describe :monitor do

    before do
      @client = TCPSocket.new(*@config[:command])

      def send method, params, client = @client
        request = { id: @id += 1, method: method, params: params }
        client.write(request.to_json + "\x00")
        request.stringify_keys
      end

      def should_receive request, expected, client = @client
        expected = expected.stringify_keys  if expected.is_a?(Hash)
        begin
          Timeout.timeout(1) do
            buf = ""
            while b = client.read(1)
              break  if b == "\x00"
              buf << b
            end
            resp = JSON.load(buf)
            expected = request.merge(result: expected).stringify_keys
            raise "ERROR: #{resp} != #{expected}"  unless resp.should == expected
          end
        rescue Timeout::Error
          print " [TIMEOUT]"
          :timeout.should == nil
        end
      end

      def store_block block
        request = send("store_block", [ block.to_payload.hth ])
        should_receive(request, {"queued" => [ "block", block.hash ]})
      end

    end

    describe :channels do

      it "should combine multiple channels" do
        request = send("monitor", ["block", "tx_1"])
        should_receive(request, ["block", [ @genesis.to_hash, 0 ]])

        store_block @block
        should_receive(request, ["block", [ @block.to_hash, 1 ]])
        should_receive(request, ["tx_1", [ @block.tx[0].to_hash, 1 ]])
      end

      it "should handle multiple clients" do
        @client2 = TCPSocket.new(*@config[:command])

        r1_1 = send "monitor", ["tx_1"]
        r1_2 = send "monitor", ["block"], @client2
        should_receive r1_2, ["block", [ @genesis.to_hash, 0 ]], @client2

        store_block @block
        should_receive r1_2, ["block", [ @block.to_hash, 1 ]], @client2
        should_receive r1_1, ["tx_1", [ @block.tx[0].to_hash, 1 ]]

        block = create_block @block.hash, false
        store_block block
        should_receive r1_2, ["block", [ block.to_hash, 2 ]], @client2
        should_receive r1_1, ["tx_1", [ block.tx[0].to_hash, 1 ]]

        r2_2 = send "monitor", ["tx_1"], @client2
        r2_1 = send "monitor", ["block"]
        should_receive r2_1, ["block", [ block.to_hash, 2 ]]

        block = create_block block.hash, false
        store_block block

        should_receive r1_2, ["block", [ block.to_hash, 3 ]], @client2
        should_receive r2_2, ["tx_1", [ block.tx[0].to_hash, 1 ]], @client2

        should_receive r1_1, ["tx_1", [ block.tx[0].to_hash, 1 ]]

        # if something was wrong, we would now receive the last tx again

        should_receive r2_1, ["block", [ block.to_hash, 3 ]]

        block = create_block block.hash, false
        store_block block
        should_receive r1_1, ["tx_1", [ block.tx[0].to_hash, 1 ]]
        should_receive r2_1, ["block", [ block.to_hash, 4 ]]
        should_receive r1_2, ["block", [ block.to_hash, 4 ]], @client2
        should_receive r2_2, ["tx_1", [ block.tx[0].to_hash, 1 ]], @client2
      end

    end

    describe :block do

      before do
        @request = send "monitor", ["block"]
        should_receive @request, ["block", [ @genesis.to_hash, 0 ]]
        store_block @block
        should_receive @request, ["block", [ @block.to_hash, 1 ]]
      end

      it "should monitor block" do
        @block = create_block @block.hash, false
        store_block @block
        should_receive @request, ["block", [ @block.to_hash, 2 ]]
      end

      it "should not monitor side or orphan blocks" do
        @side = create_block @genesis.hash, false
        store_block @side

        @orphan = create_block "00" * 32, false
        store_block @orphan

        # should not send side or orphan block only the next main block
        @block = create_block @block.hash, false
        store_block @block
        should_receive @request, ["block", [ @block.to_hash, 2 ]]
      end

      it "should received missed blocks when last height is given" do
        @client = TCPSocket.new(*@config[:command])
        blocks = [@block]
        3.times do
          blocks << create_block(blocks.last.hash, false)
          store_block blocks.last
        end
        sleep 0.1
        r = send "monitor", ["block_1"]
        should_receive r, ["block_1", [ blocks[1].to_hash, 2]]
        should_receive r, ["block_1", [ blocks[2].to_hash, 3]]
        should_receive r, ["block_1", [ blocks[3].to_hash, 4]]
      end

    end

      describe :reorg do

        before do
          @request = send "monitor", ["reorg"]
          store_block @block
        end

        it "should monitor reorg" do
          @block1 = create_block @genesis.hash, false
          store_block @block1
          @block2 = create_block @block1.hash, false
          store_block @block2
          should_receive @request, ["reorg", [ [@block1.hash], [@block.hash] ]]
        end

      end

    describe :tx do

      it "should monitor unconfirmed tx" do
        r1 = send "monitor", ["tx"]
        tx = @block.tx[0]
        r2 = send "store_tx", [ tx.to_payload.hth ]
        should_receive r2, { "queued" => [ "tx", tx.hash ]}
        should_receive r1,["tx", [ tx.to_hash, 0 ]]
      end

      it "should monitor confirmed tx" do
        r = send "monitor", ["tx_1"]
        store_block @block
        should_receive r, ["tx_1", [ @block.tx[0].to_hash, 1 ]]
      end

      it "should monitor tx for given confirmation level" do
        r = send "monitor", ["tx_3"]
        @tx = @block.tx[0]
        store_block @block
        @block = create_block @block.hash, false
        store_block @block
        should_receive r, ["tx_3", [ @genesis.tx[0].to_hash, 3 ]]
        @block = create_block @block.hash, false
        store_block @block
        should_receive r, ["tx_3", [ @tx.to_hash, 3 ]]
      end

      it "should receive missed txs when last txhash is given" do
        @client = TCPSocket.new(*@config[:command])
        blocks = [@block]; store_block @block
        3.times do
          blocks << create_block(blocks.last.hash, false)
          store_block blocks.last
        end
        sleep 0.1
        channel = "tx_1_#{blocks[0].tx[0].hash}"
        r = send "monitor", [channel]
        should_receive r, [channel, [ blocks[1].tx[0].to_hash, 3]]
        should_receive r, [channel, [ blocks[2].tx[0].to_hash, 2]]
        should_receive r, [channel, [ blocks[3].tx[0].to_hash, 1]]
      end

    end

    describe :output do

      before do
        @tx = @block.tx[0]; @out = @tx.out[0]
        @addr = Bitcoin::Script.new(@out.pk_script).get_address
      end

      it "should monitor unconfirmed outputs" do
        r1 = send "monitor", ["output"]
        tx = @block.tx[0]
        r2 = send "store_tx", [ tx.to_payload.hth ]
        should_receive r2, { "queued" => [ "tx", tx.hash ]}
        addr = Bitcoin::Script.new(tx.out[0].pk_script).get_address
        should_receive r1, ["output", { nhash: tx.nhash, hash: tx.hash, idx: 0,
                              address: addr, value: tx.out[0].value, confirmations: 0 }]
      end

      it "should monitor confirmed output" do
        r = send "monitor", ["output_1"]
        store_block @block
        should_receive r, ["output_1", { nhash: @tx.nhash, hash: @tx.hash, idx: 0,
                             address: @addr, value: @out.value, confirmations: 1 }]
      end

      it "should monitor output for given confirmation level" do
        r = send "monitor", ["output_3"]
        store_block @block
        @block = create_block @block.hash, false
        store_block @block
        tx = @genesis.tx[0]; out = tx.out[0]
        addr = Bitcoin::Script.new(out.pk_script).get_address
        should_receive r, ["output_3", { nhash: tx.nhash, hash: tx.hash, idx: 0,
                              address: addr, value: out.value, confirmations: 3 }]

        @block = create_block @block.hash, false
        store_block @block
        should_receive r, ["output_3", { nhash: @tx.nhash, hash: @tx.hash, idx: 0,
                              address: @addr, value: @out.value, confirmations: 3 }]
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
        channel = "output_1_#{blocks[0].tx[0].hash}:0"

        r = send "monitor", [channel]
        should_receive r, [channel, { nhash: blocks[1].tx[0].nhash, hash: blocks[1].tx[0].hash, idx: 0, address: @key.addr, value: 50e8, confirmations: 3 }]
        should_receive r, [channel, { nhash: blocks[2].tx[0].nhash, hash: blocks[2].tx[0].hash, idx: 0, address: @key.addr, value: 50e8, confirmations: 2 }]
        should_receive r, [channel, { nhash: blocks[3].tx[0].nhash, hash: blocks[3].tx[0].hash, idx: 0, address: @key.addr, value: 50e8, confirmations: 1 }]
      end

    end

  end

end
