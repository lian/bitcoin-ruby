require 'json'

module Bitcoin::Wallet

  # JSON-file-based keystore.
  class SimpleKeyStore

    # Initialize keystore.
    # [config] Hash of settings ({:file => "/foo/bar.json"})
    def initialize config
      @config = Hash[config.map{|k,v|[k.to_sym,v]}]
      @keys = {}
      load_keys
    end

    # List all stored keys.
    def keys
      @keys.values
    end

    # Get key for given +addr+.
    def key(addr)
      @keys[addr]
    end

    # Generate and store a new key.
    def new_key
      key = Bitcoin::Key.generate
      @keys[key.addr] = key
      save_keys
      key
    end

    def delete(addr)
      @keys.delete(addr)
      save_keys
    end

    # Export key for given +addr+ to base58 format.
    # (See Bitcoin::Key#to_base58)
    def export(addr)
      @keys[addr].to_base58
    end

    # Import key from given +base58+ string.
    # (See Bitcoin::Key.from_base58)
    def import(base58)
      key = Bitcoin::Key.from_base58(base58)
      @keys[key.addr] = key
      save_keys
      key.addr
    end

    # Load keys from file.
    # If file is emty this will generate a new key
    # and store it, creating the file.
    def load_keys
      if File.exist?(@config[:file])
        data = JSON.load(File.read(@config[:file]))
        data.map {|a, k| @keys[a] = Bitcoin::Key.from_base58(k)}
      else
        new_key; save_keys
      end
    end

    # Save keys to file.
    def save_keys
      File.open(@config[:file], 'w') do |file|
        file.write(Hash[@keys.map {|a, k| [a, k.to_base58]}].to_json)
      end
    end

  end

  # Deterministic keystore.
  class DeterministicKeyStore

    attr_reader :generator

    # Initialize keystore.
    # [config] Hash of settings ({:keys => 1, :seed => ..., :nonce => ...})
    def initialize config
      @config = Hash[config.map{|k,v|[k.to_sym,v]}]
      @config[:keys] = (@config[:keys] || 1).to_i
      @generator = Bitcoin::Wallet::KeyGenerator.new(@config[:seed], @config[:nonce])
    end

    # List all keys upto configured limit.
    def keys
      1.upto(@config[:keys].to_i).map {|i| @generator.get_key(i) }
    end

    # Get key for given +addr+.
    def key(addr)
      1.upto(@config[:keys].to_i).map do |i|
        key = @generator.get_key(i)
        return key  if key.addr == addr
      end
    end

    # Get new key (actually just increase the key limit).
    def new_key
      @config[:keys] += 1
      @generator.get_key(@config[:keys])
    end

    # Export key for given +addr+ to base58.
    # (See Bitcoin::Key.to_base58)
    def export(addr)
      key(addr).to_base58 rescue nil
    end

  end

end
