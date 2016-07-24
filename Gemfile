source 'https://rubygems.org'
gemspec

group :test do
  if ENV['TRAVIS']
    gem 'codeclimate-test-reporter', require: false
  else
    gem 'simplecov', require: false
  end
end
