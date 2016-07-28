require 'bacon'

if ENV['TRAVIS']
  require 'codeclimate-test-reporter'
  CodeClimate::TestReporter.start
else
  require 'simplecov'
  SimpleCov.start
end

require 'kerberos_authenticator'

FIXTURES_DIR = File.expand_path('../fixtures/', __FILE__)