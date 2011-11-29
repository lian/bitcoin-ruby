

    class Time
    def log_format_time
"#{Time.now.strftime('%H:%M:%S')}.#{Time.now.usec}".ljust(16)
    end
  end



module Bitcoin


  module Logger

    class CustomFormatter < Log4r::DefaultFormatter

      def format event
        color = ["\e[34m", "\e[32m", "\e[33m", "\e[1m\e[31m"][event.level-1]
        level = ["DEBUG", "INFO ", "WARN ", "ERROR", "FATAL"][event.level-1]
        "#{color}" + #{Time.now.strftime('%H:%M:%S')}.#{Time.now.usec}".ljust(16) +
          "#{event.name.ljust(8)} #{level} #{event.data}\e[0m\n"
      end

    end

    
    DEFAULTS = {
      :storage => [
                   [:stdout, :level => 0],
                  ]
    }

    def self.create name
      @log = Log4r::Logger.new(name.to_s)
      @log.level = 0
      
      pattern = "#{Time.now}\e[31m%d %c %l %m \e[0m"
      format = CustomFormatter.new
      sout = Log4r::Outputter.stdout
      sout.formatter = format
      @log.outputters << sout
      @log.outputters << Log4r::FileOutputter.new("fout", :filename => "log/#{name}.log")
      @log
    end

  end

end
