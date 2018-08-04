# frozen_string_literal: true

require_relative '../lib/bitcoin'

# Used for loading some fixtures
require 'json'
# Code coverage generation
require 'simplecov'

SimpleCov.start do
  add_group('Bitcoin') do |file|
    ['bitcoin.rb', 'opcodes.rb', 'script.rb', 'key.rb'].include?(
      file.filename.split('/').last
    )
  end
  add_group 'Protocol', 'lib/bitcoin/protocol'
  add_group('Utilities') do |file|
    ['logger.rb', 'openssl.rb'].include?(
      file.filename.split('/').last
    )
  end
end

# Require all test helper files.
Dir['./spec/helpers/**/*.rb'].sort.each { |file| require file }

# Configure external libraries
LibraryHelpers.configure_libsecp256k1

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object. This is generally recommended, and will default to
    # `true` in RSpec 4.
    mocks.verify_partial_doubles = true
  end

  # Causes shared context metadata to be inherited by the metadata hash of host
  # groups and examples, rather than triggering implicit auto-inclusion in
  # groups with matching metadata.
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # This allows you to limit a spec run to individual examples or groups
  # you care about by tagging them with `:focus` metadata. When nothing
  # is tagged with `:focus`, all examples get run. RSpec also provides
  # aliases for `it`, `describe`, and `context` that include `:focus`
  # metadata: `fit`, `fdescribe` and `fcontext`, respectively.
  config.filter_run_when_matching :focus

  # Allows RSpec to persist some state between runs in order to support
  # the `--only-failures` and `--next-failure` CLI options. We recommend
  # you configure your source control system to ignore this file.
  config.example_status_persistence_file_path = 'spec-rspec/examples.txt'

  # Limits the available syntax to the non-monkey patched syntax that is
  # recommended. For more details, see:
  #   - http://rspec.info/blog/2012/06/rspecs-new-expectation-syntax/
  #   - http://www.teaisaweso.me/blog/2013/05/27/rspecs-new-message-expectation-syntax/
  #   - http://rspec.info/blog/2014/05/notable-changes-in-rspec-3/#zero-monkey-patching-mode
  config.disable_monkey_patching!

  # This setting enables warnings. It's recommended, but in some cases may
  # be too noisy due to issues in dependencies.
  config.warnings = true

  # Many RSpec users commonly either run the entire suite or an individual
  # file, and it's useful to allow more verbose output when running an
  # individual spec file.
  if config.files_to_run.one?
    # Use the documentation formatter for detailed output,
    # unless a formatter has already been configured
    # (e.g. via a command-line flag).
    config.default_formatter = 'doc'
  end

  # Print the 10 slowest examples and example groups at the
  # end of the spec run, to help surface which specs are running
  # particularly slow.
  config.profile_examples = 10

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = :random

  # Seed global randomization in this process using the `--seed` CLI option.
  # Setting this allows you to use `--seed` to deterministically reproduce
  # test failures related to randomization by passing the same `--seed` value
  # as the one that triggered the failure.
  Kernel.srand config.seed

  # Expose DSL globally so we don't have to namespace everything
  config.expose_dsl_globally = true

  # Include fixture helpers in all tests
  config.include FixtureHelpers
  config.include BlockHelpers
  config.include Bitcoin::Builder

  # Clear the network back to bitcoin mainnet before each test
  config.before(:each) do
    Bitcoin.network = :bitcoin
  end
end
