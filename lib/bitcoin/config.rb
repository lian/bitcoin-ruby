module Bitcoin

  module Config

    CONFIG_PATHS = "./bitcoin-ruby.yml:~/.bitcoin-ruby.yml:/etc/bitcoin-ruby.yml"

    def self.load(options, categories = [], paths = CONFIG_PATHS)
      paths.split(":").reverse.each do |path|
        path.sub!("~", ENV["HOME"])
        next  unless File.exist?(path)
        options = load_file(options, path, categories)
      end
      options
    end

    def self.load_file(options, file, c = [])
      categories = YAML::load_file(file)
      [:all, *(c.is_a?(Array) ? c : [c])].each do |category|
        options = load_category(options, categories[category.to_s])  if category
      end
      options
    end

    def self.load_category(options, category)
      return options  unless category
      merge(options, category)
    end

    def self.merge(a, b)
      a.merge(b) do |k, o, n|
        o.is_a?(Hash) && n.is_a?(Hash) ? merge(o, n) : n
      end
    end

  end

end
