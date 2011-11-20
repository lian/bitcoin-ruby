$: << File.expand_path(File.join(File.dirname(__FILE__), '/../../lib'))

require 'bitcoin'

def fixtures_file(relative_path)
  basedir = File.join(File.dirname(__FILE__), 'fixtures')
  File.open(File.join( basedir, relative_path ), 'rb'){|f| f.read }
end

Bitcoin::network = :bitcoin

require 'bacon'; Bacon.summary_on_exit
