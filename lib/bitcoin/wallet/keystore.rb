# encoding: ascii-8bit

require 'json'
require 'stringio'

module Bitcoin::Wallet

  # JSON-file-based keystore used by the Wallet.
  class SimpleKeyStore

    attr_reader :config

    # Initialize keystore.
    # [config] Hash of settings ({:file => "/foo/bar.json"})
    def initialize config
      @config = Hash[config.map{|k,v|[k.to_sym,v]}]
      @config[:file].sub!("~", ENV["HOME"])  if @config[:file].is_a?(String)
      @keys = []
      load_keys
    end

    # List all stored keys.
    def keys(need = nil)
      @keys.select do |key|
        next !(key[:hidden] && key[:hidden] == "true")  unless need
        case need
        when :label
          !!key[:label]
        when :pub
          !!key[:key].pub
        when :priv
          !!key[:key].priv
        when :hidden
          !!key[:hidden]
        when :mine
          !!key[:mine]
        end
      end
    end

    # Get key for given +label+, +addr+ or +pubkey+.
    def key(name)
      find_key(name)
    end

    # Generate and store a new key.
    def new_key(label = nil)
      raise ArgumentError, "Label #{label} already in use"  if label && find_key(label)
      key = Bitcoin::Key.generate
      @keys << {:label => label, :addr => key.addr, :key => key}
      save_keys
      key
    end

    # Add a key which can consist only of +addr+ and +label+.
    def add_key key
      label = key[:label]
      raise ArgumentError, "Label #{label} already in use"  if label && find_key(label)
      addr = key[:addr]
      raise ArgumentError, "Address #{addr} is invalid"  if addr && !Bitcoin.valid_address?(addr)
      @keys << key
      save_keys
      key
    end

    def label_key(name, label)
      find_key(name) do |key|
        key[:label] = label
      end
      save_keys
    end

    def flag_key(name, flag, value)
      find_key(name, true) do |key|
        key[flag.to_sym] = value
      end
      save_keys
    end

    # Delete key for given +label+, +addr+ or +pubkey+.
    def delete(name)
      key = find_key(name)
      @keys.delete(key)
      save_keys
    end

    # Export key for given +name+ to base58 format.
    # (See Bitcoin::Key#to_base58)
    def export(name)
      find_key(name)[:key].to_base58 rescue nil
    end

    # Import key from given +base58+ string.
    # (See Bitcoin::Key.from_base58)
    def import(base58, label = nil)
      raise ArgumentError, "Label #{label} already in use"  if label && find_key(label)
      key = Bitcoin::Key.from_base58(base58)
      raise ArgumentError, "Address #{key.addr} already in use"  if label && find_key(key.addr)
      @keys << {:label => label, :addr => key.addr, :key => key}
      save_keys
      key
    end

    # Load keys from file.
    # If file is empty this will generate a new key
    # and store it, creating the file.
    def load_keys
      loader = proc{|keys|
        keys.map!{|k| Hash[k.map{|k,v| [k.to_sym, v] }]}
        keys.map do |key|
          key[:key] = Bitcoin::Key.new(key[:priv], key[:pub])
          key[:priv], key[:pub] = nil
          @keys << key
        end
      }
      if @config[:file].is_a?(StringIO)
        json = JSON.load(@config[:file].read)
        loader.call(json)
      elsif File.exist?(@config[:file])
        json = JSON.load(File.read(@config[:file]))
        loader.call(json)
      else
        new_key; save_keys
      end
    end

    # Save keys to file.
    def save_keys
      dumper = proc{|file|
        keys = @keys.map do |key|
          key = key.dup
          if key[:key]
            key[:priv] = key[:key].priv
            key[:pub] = key[:key].pub
            key.delete(:key)
          end
          key
        end
        file.write(JSON.pretty_generate(keys))
      }

      if @config[:file].is_a?(StringIO)
        @config[:file].reopen
        dumper.call(@config[:file])
        @config[:file].rewind
      else
        File.open(@config[:file], 'w'){|file| dumper.call(file) }
      end
    end

    private

    def find_key(name, hidden = false)
      key = if Bitcoin.valid_address?(name)
              @keys.find{|k| k[:addr] == name }
            elsif name.size == 130
              @keys.find{|k| k[:key].pub == name }
            else
              @keys.find{|k| k[:label] == name }
            end
      return nil  if !key || (!hidden && key[:hidden] == "true")
      block_given? ? yield(key) : key
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
