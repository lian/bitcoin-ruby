# encoding: ascii-8bit

begin
  require 'log4r'
  # monkey-patch Log4r to accept level names as symbols
  class Log4r::Logger
    def level= l = 0
      _level = l.is_a?(Fixnum) ? l : Log4r::LNAMES.index(l.to_s.upcase)
      Log4r::Log4rTools.validate_level(_level)
      @level = _level
      LoggerFactory.define_methods(self)
      Log4r::Logger.log_internal {"Logger '#{@fullname}' set to #{LNAMES[@level]}"}
      @level
    end
  end
rescue LoadError
end

module Bitcoin
  # this is a very simple logger that is used if log4r is not available
  module Logger

    module TimeLogger

      def time message
        time = Time.now
        res = yield
        debug { message % (Time.now - time) }
        res
      end

    end

    class Logger
      LEVELS = [:debug, :info, :warn, :error, :fatal]

      include TimeLogger

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
          puts "#{level.to_s.upcase.ljust(5)} #{@name}: #{msg}"
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
    def self.create name, level = :info
      if defined?(Log4r)
        dir = "log"
        FileUtils.mkdir_p(dir) rescue dir = nil
        @log = Log4r::Logger.new(name.to_s)
        @log.extend(TimeLogger)
        @log.level = level
        @log.outputters << Log4r::Outputter.stdout
        @log.outputters << Log4r::FileOutputter.new("fout", :filename => "#{dir}/#{name}.log")  if dir
      else
        @log = Bitcoin::Logger::Logger.new(name)
      end
      @log
    end

  end
end
