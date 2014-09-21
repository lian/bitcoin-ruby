# encoding: ascii-8bit

$: << File.expand_path(File.join(File.dirname(__FILE__), '/../../lib'))

begin
  require 'simplecov'
  SimpleCov.start do
    add_group("Bitcoin") do |file|
      ["bitcoin.rb", "opcodes.rb", "script.rb", "key.rb"].include?(file.filename.split("/").last)
    end
    add_group "Protocol", "lib/bitcoin/protocol"
    add_group("Utilities") do |file|
      ["logger.rb", "openssl.rb"].include?(file.filename.split("/").last)
    end
  end
rescue LoadError
end

require 'bitcoin'

def fixtures_path(relative_path)
  File.join(File.dirname(__FILE__), 'fixtures', relative_path)
end

def fixtures_file(relative_path)
  Bitcoin::Protocol.read_binary_file( fixtures_path(relative_path) )
end


include Bitcoin::Builder

# create block for given +prev+ block
# if +store+ is true, save it to @store
# accepts an array of +tx+ callbacks
def create_block prev, store = true, tx = [], key = Bitcoin::Key.generate, coinbase_value = 50e8, opts = {}
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
  :checkpoints => {},
  :min_tx_fee => 10_000,
  :min_relay_tx_fee => 10_000,
  :free_tx_bytes => 1_000,
  :dust => 1_000_000,
  :per_dust_fee => false,
}

begin
  require 'bacon'
rescue LoadError
  puts "Cannot load 'bacon' - install with `gem install bacon`"
  puts "Note: to run all the tests, you will also need: ffi, sequel, sqlite3"
  exit 1
end
Bacon.summary_on_exit

begin
  require 'minitest'
rescue LoadError
end
require 'minitest/mock'
include MiniTest

class Time
  class << self
    alias_method :real_new, :new
    alias_method :new, :now
    def now; @time || real_new; end
    def freeze(time = nil)
      begin
        prev = @time
        @time = time || now
        yield
      ensure
        @time = prev
      end
    end
    def frozen?; !@time.nil?; end
  end
end
