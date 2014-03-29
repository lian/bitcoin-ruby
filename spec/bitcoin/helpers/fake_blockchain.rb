require_relative '../spec_helper'
require 'fileutils'

Bitcoin::NETWORKS[:fake] = {
  :project => :bitcoin,
  :no_difficulty => true,
  :magic_head => "fake",
  :address_version => "00",
  :p2sh_version => "05",
  :privkey_version => "80",
  :default_port => 78333,
  :coinbase_maturity => 0,
  :protocol_version => 70001,
  :max_money => 21_000_000 * 100_000_000,
  :dns_seeds => [],
  :genesis_hash => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
  :proof_of_work_limit => 553713663,
  :alert_pubkeys => [],
  :known_nodes => [],
  :checkpoints => {},
  :min_tx_fee => 10_000,
  :min_relay_tx_fee => 10_000,
}



# Small utility to generate fake blocks mostly to be able to test performance
# They are full from the start, so that we don't have to import 100K blocks to check
# how performance looks when storing or validating 1K transactions
class FakeBlockchain

  # Initialize fake blockchain and generate +num_blocks+ starting blocks with given
  # +opts+ (see #generate).
  def initialize(num = 50, opts = {})
    Bitcoin.network = :fake
    if File.exist? block_path(0)
      genesis = Bitcoin::P::Block.new File.read block_path 0
      Bitcoin.network[:genesis_hash] = genesis.hash
    else
      STDERR.puts "\nFake blockchain not present, generating (go take a nap)..."
      depth = 0
      FileUtils.mkdir_p fixtures_path "fake_chain"
      generate(num, opts) do |blk|
        File.open(block_path(depth),'w') {|f| f.write blk.to_payload }
        depth += 1
      end
    end
  end

  # Generate fake blockchain with +num+ number of blocks
  # Blocks are provided as an argument to the block given to the method
  #   fake_chain.generate(5) {|b| save_block(b) }
  def generate(num = 50, opts = {})
    srand 1337

    default_opts = {
      block_size: 950_000, # minimum block size
      num_keys: 1000, # number of different keys being used
      genesis_timestamp: Time.new(2009).to_i,
      verbose: true, # print out debug information
    }

    opts = default_opts.merge(opts)

    to_spend = [] # table of outputs that we can spend
    lost_count = 0 # keeping track of lost coins
    keys = Array.new(opts[:num_keys]) { Bitcoin::Key.generate }
    timestamp = opts[:genesis_timestamp]

    genesis = Bitcoin::Builder.build_block do |blk|
       blk.time timestamp
       blk.prev_block "00"*32
       blk.tx do |t|
         t.input {|i| i.coinbase }
         t.output {|o| o.value 50*Bitcoin::COIN; o.script {|s| s.recipient keys[0].addr } }
       end
    end
    Bitcoin.network[:genesis_hash] = genesis.hash
    yield(genesis)

    to_spend << {tx: genesis.tx[0], tx_idx: 0, key: keys[0], value: 50e8}

    prev_block = genesis


    num.times do |blk_i|

      timestamp += 600
      t0 = Time.now

      block = Bitcoin::Builder.build_block do |blk|
        blk.time timestamp
        blk.prev_block prev_block.hash
        key0 = keys.sample
        tx0 = blk.tx do |t|
          t.input {|i| i.coinbase }
          t.output {|o| o.value 50e8; o.script {|s| s.recipient key0.addr } }
        end

        # We "lose" some coins, that is we decide never to spend some outputs
        # It's to keep utxo growing without making block generation time growing
        lost_count += to_spend.size
        to_spend = to_spend.reject.with_index {|x,i| i==0 ? false : (((to_spend.size - i) / to_spend.size.to_f)**2 * rand > rand*0.2) }
        lost_count -= to_spend.size

        # many txs vs many tx outputs in given block
        many_outputs_prob = 0.5 * (rand ** 3)

        total_tx_size = 0

        # generate tranasctions
        loop do
          # we want utxo to keep growing so we use many inputs only with some small probability
          ins = to_spend[(rand(to_spend.size)).to_i..-1].sample(rand < 0.01 ? (rand(50) + 1) : 1)
          total = ins.map{|i| i[:value]}.inject(:+)
          next if total < 20_000

          new_outs = []

          tx = blk.tx do |t|

            # generate inputs
            ins.map do |input|
              t.input do |i|
                i.prev_out input[:tx]
                i.prev_out_index input[:tx_idx]
                i.signature_key input[:key]
              end
            end
            # remove outputs that we just used
            ins.each {|i| to_spend.delete i}

            fee = 10_000
            # helper to split value randomly in a half
            half_split = ->(v) { split = [rand, 0.1].max; [v*split, v*(1-split)] }
            # helper to split value randomly to many pieces
            value_split = ->(v, depth=0) {(depth < 10 && rand > 0.2) ? half_split[v].map{|x| value_split[x, depth+1]} : [v] }

            if rand < many_outputs_prob
              # every now and then there are many outptus
              out_values = value_split[total-fee].flatten.map {|x| x.round(8)}
              out_values.each.with_index do |v,i|
                key = keys.sample
                t.output {|o| o.value v; o.script {|s| s.recipient key.addr }}
                new_outs << {tx_idx: i, key: key, value: v}
              end
            else
              # most txs seem to have 2 outputs
              k1 = keys.sample
              k2 = keys.sample
              v1, v2 = half_split[total-fee]
              t.output {|o| o.value v1; o.script {|s| s.recipient k1.addr }}
              t.output {|o| o.value v2; o.script {|s| s.recipient k2.addr }}
              new_outs << {tx_idx: 0, key: k1, value: v2}
              new_outs << {tx_idx: 1, key: k2, value: v2}
            end
          end

          new_outs.each {|o| to_spend << {tx: tx}.merge(o) } # fun fact: the opposite merge is way slower

          total_tx_size += tx.to_payload.size
          break if total_tx_size > opts[:block_size]
        end

        # coinbase
        to_spend << {tx: tx0, tx_idx: 0, key: key0, value: 50e8}
      end
      puts "depth #{blk_i+1}/#{num} \t txcount: #{block.tx.size} \t size: #{block.to_payload.size} \t utxo count: #{to_spend.size + lost_count} (#{to_spend.size}) \t ttg: #{'%.2f' % (Time.now - t0)}s" if opts[:verbose]
      yield(block)
      prev_block = block
    end
    true
  end

  def block(depth)
    Bitcoin::Protocol::Block.new File.read block_path depth
  end

  def block_path(depth)
    fixtures_path "fake_chain/#{depth}.blk"
  end

end
