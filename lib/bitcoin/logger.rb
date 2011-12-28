begin
  require 'log4r'
  # monkey-patch Log4r to accept level names as symbols
  class Log4r::Logger
    def level= l
      @level = l.is_a?(Fixnum) ? l : Log4r::LNAMES.index(l)
    end
  end
rescue LoadError
  # log4r not installed
end

module Bitcoin
  # this is a very simple logger that is used if log4r is not available
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
          puts "#{level.to_s.upcase.ljust(5)} #{@name} #{msg}"
        end
      end
    end

    # wrap a logger and prepend a special name in front of the messages
    class LogWrapper
      def initialize(name, log); @name, @log = name, log; end
      def method_missing(m, *a, &blk)
        @log.send(m, *a, &proc{ "#{@name} #{blk.call}" })
      end
    end

    # create a logger with given +name+. if log4r is installed, the logger
    # will have a stdout and a fileout outputter to `log/<name>.log`.
    # otherwise, the internal dummy logger is used which only logs to stdout.
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
