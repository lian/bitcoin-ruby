source "http://rubygems.org"

# Specify your gem's dependencies in bitcoin-ruby.gemspec
gemspec

group :test do 
  gem 'sqlite3', :platforms => :ruby

  gem 'bacon', '>= 1.2.0'
  gem 'simplecov', :require => false

  gem 'rake', '>= 0.8.0'
end

group :development do
  gem 'eventmachine'
  gem 'ffi'
  gem 'log4r'
  gem 'sequel'

  gem 'sqlite3', :platforms => :ruby, :require => false
  gem 'pg', :platforms => :ruby, :require => false

  gem "rake", ">= 0.8.0"
end
