require File.expand_path('../lib/kerberos_authenticator/version', __FILE__)

Gem::Specification.new do |s|
  s.name        = 'kerberos_authenticator'
  s.version     = KerberosAuthenticator::VERSION
  s.summary     = 'Authenticate a Kerberos user using their password. Uses Ruby-FFI to interface with the Kerberos library.'
  s.authors     = ['Adam Watkins']
  s.files       = Dir['lib/**/*.rb', 'lib/kerberos_authenticator.rb']
  s.license     = 'MIT'
  s.homepage    = 'https://github.com/stupidpupil/kerberos_authenticator'
  s.requirements << 'A Kerberos 5 library'

  s.add_runtime_dependency 'ffi', '~> 1.9'
  s.add_development_dependency 'bacon', '~> 1.2'
end
