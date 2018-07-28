# frozen_string_literal: true

module LibraryHelpers
  LIBSECP256K1_ENVVAR = 'SECP256K1_LIB_PATH'

  # Help configure path to libsecp256k1. Automatically handles setting path to
  # build output if present.
  def self.configure_libsecp256k1
    return if ENV[LIBSECP256K1_ENVVAR]
    return unless File.exist?('secp256k1.so')

    ENV[LIBSECP256K1_ENVVAR] = File.join(Dir.pwd, 'secp256k1.so')
  end
end
