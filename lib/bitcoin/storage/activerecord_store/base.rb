module Bitcoin::Storage::Backends::ActiverecordStore

  module Base
    
    def self.included(base)
      base.extend Bitcoin::Util
      base.instance_eval do
        
        def log
          Bitcoin::Storage.log
        end
      end
    end
  end

end
