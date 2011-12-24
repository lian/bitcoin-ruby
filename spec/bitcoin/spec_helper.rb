$: << File.expand_path(File.join(File.dirname(__FILE__), '/../../lib'))

begin
  require 'simplecov'
  SimpleCov.start do
    add_group("Bitcoin") do |file|
      ["bitcoin.rb", "script.rb", "key.rb"].include?(file.filename.split("/").last)
    end
    add_group "Protocol", "lib/bitcoin/protocol"
    add_group "Storage", "lib/bitcoin/storage"
    add_group("Utilities") do |file|
      ["logger.rb", "openssl.rb"].include?(file.filename.split("/").last)
    end
  end
rescue LoadError
end

require 'bitcoin'

def fixtures_file(relative_path)
  basedir = File.join(File.dirname(__FILE__), 'fixtures')
  File.open(File.join( basedir, relative_path ), 'rb'){|f| f.read }
end

Bitcoin::network = :bitcoin

require 'bacon'; Bacon.summary_on_exit
