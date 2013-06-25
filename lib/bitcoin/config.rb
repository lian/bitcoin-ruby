# encoding: ascii-8bit

require 'yaml'
module Bitcoin

  # Load config files, merge options, etc.
  #
  # Multiple config files are loaded in order, and their settings merged into an
  # existing +options+ hash.
  #
  # Each config file defines one or more +categories+ which hold the actual settings.
  # Which categories are loaded, and in what order, is specified when you load
  # the config (ie. the order in the file doesn't matter).
  # The default category "all" is always used, and is always the first
  # (gets overridden by all others)
  module Config

    CONFIG_PATHS = "./bitcoin-ruby.yml:~/.bitcoin-ruby.yml:/etc/bitcoin-ruby.yml"

    # Load +categories+ from all files at +paths+ into given +options+ hash.
    def self.load(options, categories = [], paths = CONFIG_PATHS)
      paths.split(":").reverse.each do |path|
        path.sub!("~", ENV["HOME"])
        next  unless File.exist?(path)
        options = load_file(options, path, categories)
      end
      options
    end

    # Load categories +c+ of a single config +file+ into given +options+ hash.
    def self.load_file(options, file, c = [])
      categories = YAML::load_file(file)
      [:all, *(c.is_a?(Array) ? c : [c])].each do |category|
        options = merge(options, categories[category.to_s])  if categories[category.to_s]
      end
      options
    end

    # Deep-merge hash +b+ into +a+.
    def self.merge(a, b)
      return a unless b
      symbolize(a).merge(symbolize(b)) do |k, o, n|
        if o.is_a?(Hash) && n.is_a?(Hash)
          merge(symbolize(o), symbolize(n))
        else
          n
        end
      end
    end

    # Turn all keys in +hash+ into symbols.
    def self.symbolize(hash)
      Hash[hash.map{|k,v|[k.to_sym,v]}]
    end

  end

end
