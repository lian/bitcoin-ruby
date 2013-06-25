# encoding: ascii-8bit

module Bitcoin::Wallet

  # Deterministic key generator as described in
  # https://bitcointalk.org/index.php?topic=11665.0.
  #
  # Takes a seed and generates an arbitrary amount of keys.
  # Protects against brute-force attacks by requiring the
  # key hash to fit a difficulty target, much like the block chain.
  class KeyGenerator

    # difficulty target (0x0000FFFF00000000000000000000000000000000000000000000000000000000)
    DEFAULT_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000

    attr_accessor :seed, :nonce, :target

    # Initialize key generator with optional +seed+ and +nonce+ and +target+.
    # [seed] the seed data for the keygenerator (default: random)
    # [nonce] the nonce required to satisfy the target (default: computed)
    # [target] custom difficulty target (default: DEFAULT_TARGET)
    #
    # Example:
    #  g = KeyGenerator.new # random seed, computed nonce, default target
    #  KeyGenerator.new(g.seed)
    #  KeyGenerator.new(g.seed, g.nonce)
    #  g.get_key(0) #=> <Bitcoin::Key>
    #
    # Note: When initializing without seed, you should obviously save the
    # seed once it is generated. Saving the nonce is optional; it only saves time.
    def initialize seed = nil, nonce = nil, target = nil
      @seed = seed || OpenSSL::Random.random_bytes(64)
      @target = target || DEFAULT_TARGET
      @nonce = check_nonce(nonce)
    end

    # get key number +n+ from chain
    def get_key(n = 0)
      key = get_hash(@seed, @nonce)
      (n + 1).times { key = sha256(key) }
      key
      Bitcoin::Key.new(key.unpack("H*")[0])
    end

    # find a nonce that leads to the privkey satisfying the target
    def find_nonce
      n = 0
      n += 1  while !check_target(get_hash(@seed, n))
      n
    end

    protected

    # check the nonce; compute if missing, raise if invalid.
    def check_nonce(nonce)
      return find_nonce  unless nonce
      # check_target(get_hash(@seed, nonce)) ? nonce : find_nonce
      raise ArgumentError, "Nonce invalid."  unless check_target(get_hash(@seed, nonce))
      nonce
    end

    # check if given +hash+ satisfies the difficulty target
    def check_target(hash)
      hash.unpack("H*")[0].to_i(16) < @target
    end

    # compute a single SHA256 hash for +d+.
    def sha256(d); Digest::SHA256.digest(d); end

    # get the hash corresponding to +seed+ and +n+.
    def get_hash(seed, n)
      sha256( sha256(seed) + sha256(n.to_s) )
    end

  end

end
