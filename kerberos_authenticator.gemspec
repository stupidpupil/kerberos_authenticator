Gem::Specification.new do |s|
  s.name        = 'kerberos_authenticator'
  s.version     = '0.0.1'
  s.summary     = 'An FFI library to support Kerberos authentication of a user, with a password, and of the KDC, with a keytab'
  s.authors     = ['Adam Watkins']
  s.files       = Dir['lib/**/*.rb', 'lib/kerberos_authenticator.rb']
  s.license     = 'MIT'
  s.homepage    = 'https://github.com/stupidpupil/kerberos_authenticator'
  s.requirements << 'A Kerberos 5 library'
end
