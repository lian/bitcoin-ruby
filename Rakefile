require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

# libsecp256k1 repository URL
LIBSECP256K1_REPO = 'https://github.com/bitcoin-core/secp256k1/'.freeze
# Folder into which libsecp256k1 repository is cloned
LIBSECP256K1_PATH = 'secp256k1'.freeze

RUBY = 'ruby' unless defined?(RUBY)

# Attempts to configure the path to libsecp256k1.
#
# @return [Bool] true if the library was found and configured, false otherwise.
def configure_libsecp256k1
  return true if ENV["SECP256K1_LIB_PATH"]

  if File.exist?('secp256k1.so')
    ENV['SECP256K1_LIB_PATH'] = File.join(Dir.pwd, 'secp256k1.so')
    return true
  end

  false
end

task :default => :rspec

RSpec::Core::RakeTask.new(:rspec) do |t|
  t.rspec_opts = '--exclude spec/unit/integrations/*'
end

RSpec::Core::RakeTask.new(:coin_spec, :coin) do |t, args|
  t.rspec_opts = "--pattern spec/unit/integrations/#{args[:coin]}_spec.rb"
end

desc 'Compiles the libsecp256k1 library'
task :build_libsecp256k1, [:force] do |_, args|
  # Commit hash for libsecp256k1 from May 31, 2018.
  COMMIT_HASH = '1e6f1f5ad5e7f1e3ef79313ec02023902bf8175c'.freeze

  force = args[:force]

  if Dir.exists?(LIBSECP256K1_PATH) && !force
    puts "ERROR: Folder #{LIBSECP256K1_PATH} already exists, run with " \
         "[force:true] to force cloning and building anyways."
    exit 1
  end

  sh "rm -rf #{LIBSECP256K1_PATH}"
  sh "git clone #{LIBSECP256K1_REPO}"
  Dir.chdir(LIBSECP256K1_PATH) do
    sh "git checkout #{COMMIT_HASH}"
    sh './autogen.sh'
    sh './configure --enable-module-recovery --with-pic'
    sh 'make libsecp256k1.la'
  end

  libfile = 'libsecp256k1.so.0.0.0'
  # Handle macOS libraries being different from Linux libraries
  libfile = 'libsecp256k1.0.dylib' unless RUBY_PLATFORM.match(/darwin/).nil?
  sh "cp #{LIBSECP256K1_PATH}/.libs/#{libfile} secp256k1.so"
  sh "rm -rf #{LIBSECP256K1_PATH}"
end

desc 'Generate RDoc documentation'
task :rdoc do
  `rm -rf rdoc`
  system("rdoc -a -A -H -t 'bitcoin-ruby RDoc' -W 'https://github.com/mhanne/bitcoin-ruby/tree/master/%s' -o rdoc -m README.rdoc examples/ doc/ lib/ README.rdoc COPYING")
end

desc 'Generate test coverage report'
task :coverage do
  if !configure_libsecp256k1
    puts 'ERROR: Skipping code coverage tests since required library '\
         'libsecp256k1 was not found. Run `rake build_libsecp256k1` to build.'
    exit 1
  end

  begin
    require 'simplecov'
  rescue LoadError
    puts "Simplecov not found. Run `gem install simplecov` to install it."
    exit
  end

  Rake::Task['rspec'].invoke
  system('open coverage/index.html') if RUBY_PLATFORM.include? 'darwin'
end
