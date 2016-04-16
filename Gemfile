source 'https://rubygems.org'
gemspec

gem 'ffi'

group :test do
  gem 'bacon'

  if ENV['TRAVIS']
    gem 'codeclimate-test-reporter', require: false
  else
    gem 'simplecov', require: false
  end
end