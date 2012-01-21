module Bitcoin

  module Config

    CONFIG_PATHS = "./bitcoin-ruby.yml:~/.bitcoin-ruby.yml:/etc/bitcoin-ruby.yml"

    def self.load(options, category = nil, paths = CONFIG_PATHS)
      paths.split(":").reverse.each do |path|
        path.sub!("~", ENV["HOME"])
        next  unless File.exist?(path)
        options = load_file(options, path, category)
      end
      options
    end

    def self.load_file(options, file, category = nil)
      categories = YAML::load_file(file)
      options = load_category(options, categories["all"])
      options = load_category(options, categories[category.to_s])  if category
      options
    end

    def self.load_category(options, category)
      return options  unless category
      category.map{|k,v| options[k.to_sym] = v }
      options
    end
  end

end
