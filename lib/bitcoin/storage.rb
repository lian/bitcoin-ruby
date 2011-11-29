require 'active_record'

require_relative 'storage/block_chain'
require_relative 'storage/block'
require_relative 'storage/transactions_parent'
require_relative 'storage/transaction'
require_relative 'storage/input'
require_relative 'storage/output'

module Bitcoin::Storage

  def self.connect config
    ActiveRecord::Base.establish_connection config
  end

  @log = Bitcoin::Logger.create(:storage)

  def self.log
    @log
  end

  module StorageModel

#    include Bitcoin::Util

    def log
      Bitcoin::Storage::log
    end

    def hth(h); h.unpack("H*")[0]; end
    def htb(h); [h].pack("H*"); end
    
    def bts data
      connection.escape_bytea(data)
    end

  end
  self.constants.each do |c|
    const = const_get(c)
    const.extend(StorageModel)
  end

end

ActiveRecord::Base.logger = Bitcoin::Logger.create(:database)
