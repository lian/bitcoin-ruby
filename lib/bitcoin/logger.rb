module Bitcoin
  module Logger

    class Logger
      LEVELS = [:debug, :info, :warn, :error, :fatal]

      attr_accessor :level

      def initialize(name)
        @name, @level = name, :info
      end

      def level= level
        @level = level.is_a?(Fixnum) ? LEVELS[level] : level.to_sym
      end

      LEVELS.each do |level|
        define_method(level) do |*msg, &block|
          return  if LEVELS.index(level.to_sym) < LEVELS.index(@level.to_sym)
          msg = block ? block.call : msg.join
          puts "#{@name} #{level}: #{msg}"
        end
      end
    end

    def self.create name
      if defined?(Log4r)
        @log = Log4r::Logger.new(name.to_s)
        @log.level = 0
        @log.outputters << Log4r::Outputter.stdout
        @log.outputters << Log4r::FileOutputter.new("fout", :filename => "log/#{name}.log")
      else
        @log = Bitcoin::Logger::Logger.new(name)
      end
      @log
    end

  end
end
