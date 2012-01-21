module Bitcoin

  module Config

    CONFIG_PATHS = "./bitcoin-ruby.yml:~/.bitcoin-ruby.yml:/etc/bitcoin-ruby.yml"

    def self.load(options, paths = CONFIG_PATHS)
      paths.split(":").reverse.each do |path|
        path.sub!("~", ENV["HOME"])
        next  unless File.exist?(path)
        options = load_file(options, path)
      end
      options
    end

    def self.load_file(options, file)
      YAML::load_file(file).map{|k,v| options[k.to_sym] = v }
      options
    end

  end

end
