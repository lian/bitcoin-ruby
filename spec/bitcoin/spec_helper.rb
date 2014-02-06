# encoding: ascii-8bit

$: << File.expand_path(File.join(File.dirname(__FILE__), '/../../lib'))

begin
  require 'simplecov'
  SimpleCov.start do
    add_group("Bitcoin") do |file|
      ["bitcoin.rb", "opcodes.rb", "script.rb", "key.rb"].include?(file.filename.split("/").last)
    end
    add_group "Protocol", "lib/bitcoin/protocol"
    add_group "Storage", "lib/bitcoin/storage"
    add_group "Wallet", "lib/bitcoin/wallet"
    add_group("Utilities") do |file|
      ["logger.rb", "openssl.rb"].include?(file.filename.split("/").last)
    end
  end
rescue LoadError
end

require 'bitcoin'

def fixtures_file(relative_path)
  basedir = File.join(File.dirname(__FILE__), 'fixtures')
  Bitcoin::Protocol.read_binary_file( File.join(basedir, relative_path) )
end

include Bitcoin::Builder

# create block for given +prev+ block
# if +store+ is true, save it to @store
# accepts an array of +tx+ callbacks
def create_block prev, store = true, tx = [], key = Bitcoin::Key.new, coinbase_value = 50e8, opts = {}
  opts[:bits] ||= Bitcoin.network[:proof_of_work_limit]
  block = build_block(Bitcoin.decode_compact_bits(opts[:bits])) do |b|
    b.time opts[:time]  if opts[:time]
    b.prev_block prev
    b.tx do |t|
      t.input {|i| i.coinbase }
      t.output {|o| o.value coinbase_value; o.script {|s| s.recipient key.addr } }
    end
    tx.each {|cb| b.tx {|t| cb.call(t) } }
  end
  @store.store_block(block)  if store
  block
end

# create transaction given builder +tx+
# +outputs+ is an array of [value, key] pairs
def create_tx(tx, prev_tx, prev_out_index, outputs, key = @key)
  tx.input {|i| i.prev_out prev_tx; i.prev_out_index prev_out_index; i.signature_key key }
  outputs.each do |value, key|
    tx.output {|o| o.value value; o.script {|s| s.recipient key.addr } }
  end
end

# create a chain of +n+ blocks, based on +prev_hash+ block.
# influence chain properties via options:
#  time: start time all other times are based on
#  interval: time between blocks
#  bits: target bits each block must match
def create_blocks prev_hash, n, opts = {}
  interval = opts[:interval] || 600
  time = opts[:time] || Time.now.to_i
  bits = opts[:bits] || 553713663
  block = @store.get_block(prev_hash)
  n.times do |i|
    block = create_block block.hash, true, [], @key, 50e8, {
      time: time += interval, bits: bits }
    # block = @store.get_block(block.hash)
    # puts "#{i} #{block.hash[0..8]} #{block.prev_block.reverse_hth[0..8]} #{Time.at(block.time).strftime('%Y-%m-%d %H:%M:%S')} c: #{block.chain} b: #{block.bits} n: #{block.nonce} w: #{block.work}"
  end
  block
end


Bitcoin::network = :bitcoin

Bitcoin::NETWORKS[:spec] = {
  :project => :bitcoin,
  :magic_head => "spec",
  :address_version => "6f",
  :p2sh_version => "c4",
  :privkey_version => "ef",
  :default_port => 48333,
  :protocol_version => 70001,
  :max_money => 21_000_000 * 100_000_000,
  :dns_seeds => [],
  :genesis_hash => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
  :proof_of_work_limit => 553713663,
  :alert_pubkeys => [],
  :known_nodes => [],
  :checkpoints => {}
}

begin
  require 'bacon'
rescue LoadError
  puts "Cannot load 'bacon' - install with `gem install bacon`"
  puts "Note: to run all the tests, you will also need: ffi, sequel, sqlite3"
  exit 1
end
Bacon.summary_on_exit
require 'minitest/mock'

require 'sequel'
def setup_db backend, db = nil, conf = {}
  uri = case db
        when :sqlite
          "sqlite:/"
        when :postgres
          ENV["TEST_DB_POSTGRES"].dup rescue nil
        when :mysql
          ENV["TEST_DB_MYSQL"].dup rescue nil
        end
  if [:postgres, :mysql].include?(db)
    unless uri
      puts "Skipping #{db} tests"  
      return nil
    end
    db = Sequel.connect(uri)
    db.drop_table(*db.tables, cascade: true)
  end
  Bitcoin::Storage.send(backend, conf.merge(db: uri, log_level: :warn))
end
