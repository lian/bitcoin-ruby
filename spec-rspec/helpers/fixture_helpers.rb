# frozen_string_literal: true

# Helpers for interacting with fixture data.
module FixtureHelpers
  # Return path to fixture given a relative path.
  #
  # @param relative_path [String] relative path to fixture.
  # @return [String] path to fixture corresponding to relative_path.
  def fixtures_path(relative_path)
    File.join(File.dirname(__FILE__), '..', 'fixtures', relative_path)
  end

  # Return the binary contents of the given file.
  #
  # @param relative_path [String] relative path to fixture.
  # @return [String] binary data read from the fixture file.
  def fixtures_file(relative_path)
    Bitcoin::Protocol.read_binary_file(fixtures_path(relative_path))
  end
end
