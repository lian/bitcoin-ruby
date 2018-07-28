begin
  require 'bundler/gem_tasks'
rescue LoadError
end

begin
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new(:rspec) do |t|
    t.rspec_opts = '--pattern spec-rspec/\*\*\{,/\*/\*\*\}/\*_spec.rb --default-path spec-rspec'
  end
rescue LoadError
end

# libsecp256k1 repository URL
LIBSECP256K1_REPO = 'https://github.com/bitcoin-core/secp256k1/'.freeze
# Folder into which libsecp256k1 repository is cloned
LIBSECP256K1_PATH = 'secp256k1'.freeze

PROJECT_SPECS = ( FileList['spec/bitcoin/bitcoin_spec.rb'] +
                  FileList['spec/bitcoin/protocol/*_spec.rb'] +
                  FileList['spec/bitcoin/script/*_spec.rb'] +
                  FileList['spec/bitcoin/trezor/*_spec.rb'] +
                  FileList['spec/bitcoin/*_spec.rb'] ).uniq

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

task :default => :bacon
#
# test runner
#
desc 'Run all bacon specs with pretty output'
task :bacon do
  require 'open3'
  require 'scanf'
  require 'matrix'

  specs = PROJECT_SPECS

  if !configure_libsecp256k1
    puts 'WARNING: Skipping tests that required libsecp256k1. Run ' \
         '`rake build_libsecp256k1` to build.'

    specs.delete_if do |spec|
      ['secp256k1_spec.rb', 'bip143_spec.rb'].include?(File.basename(spec))
    end
  end

  # E.g. SPEC=specs/bitcoin/script/ to run script-related specs only.
  spec_mask = ENV["SPEC"]
  if !spec_mask.nil?
    specs.delete_if{|s| !s[spec_mask] }
  end

  some_failed = false
  specs_size = specs.size
  len = specs.map{|s| s.size }.sort.last
  total_tests = total_assertions = total_failures = total_errors = 0
  totals = Vector[0, 0, 0, 0]

  red, yellow, green = "\e[31m%s\e[0m", "\e[33m%s\e[0m", "\e[32m%s\e[0m"
  left_format = "%4d/%d: %-#{len + 11}s"
  spec_format = "%d specifications (%d requirements), %d failures, %d errors"

  specs.each_with_index do |spec, idx|
    print(left_format % [idx + 1, specs_size, spec])

    Open3.popen3(RUBY, spec) do |sin, sout, serr|
      out = sout.read.strip
      err = serr.read.strip

      # this is conventional, see spec/innate/state/fiber.rb for usage
      if out =~ /^Bacon::Error: (needed .*)/
        puts(yellow % ("%6s %s" % ['', $1]))
      else
        total = nil

        out.each_line do |line|
          scanned = line.scanf(spec_format)

          next unless scanned.size == 4

          total = Vector[*scanned]
          break
        end

        if total
          totals += total
          tests, assertions, failures, errors = total_array = total.to_a

          if tests > 0 && failures + errors == 0
            puts((green % "%6d passed") % tests)
          else
            some_failed = true
            puts(red % "       failed")
            puts out unless out.empty?
            puts err unless err.empty?
          end
        else
          some_failed = true
          puts(red % "       failed")
          puts out unless out.empty?
          puts err unless err.empty?
        end
      end
    end
  end

  total_color = some_failed ? red : green
  puts(total_color % (spec_format % totals.to_a))
  exit 1 if some_failed
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

  sh "bacon", *PROJECT_SPECS
  system('open coverage/index.html') if RUBY_PLATFORM.include? 'darwin'
end
