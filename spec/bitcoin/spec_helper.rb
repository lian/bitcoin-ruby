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
