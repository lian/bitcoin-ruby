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

# create block for given +prev+ block
# if +store+ is true, save it to @store
# accepts an array of +tx+ callbacks
def create_block prev, store = true, tx = [], key = Bitcoin::Key.new, coinbase_value = 50e8
  block = blk(Bitcoin.decode_compact_bits(Bitcoin.network[:proof_of_work_limit])) do |b|
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
def create_tx(tx, prev_tx, prev_out_index, outputs)
  tx.input {|i| i.prev_out prev_tx; i.prev_out_index prev_out_index; i.signature_key @key }
  outputs.each do |value, key|
    tx.output {|o| o.value value; o.script {|s| s.recipient key.addr } }
  end
end


Bitcoin::network = :bitcoin

begin
  require 'bacon'
rescue LoadError
  puts "Cannot load 'bacon' - install with `gem install bacon`"
  puts "Note: to run all the tests, you will also need: ffi, sequel, sqlite3"
  exit 1
end
Bacon.summary_on_exit
require 'minitest/mock'
