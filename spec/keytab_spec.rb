# Run some basic specs on Krb5::Keytab to check that:
# - the FFI interface can load the library and call functions
# - the error handling in the FFI interface is working
describe KerberosAuthenticator::Krb5::Keytab do

  describe 'when I try to resolve the default Keytab' do
    it 'must return a Keytab' do
      a_keytab = lambda { |obj| obj.is_a?(KerberosAuthenticator::Krb5::Keytab) }
      KerberosAuthenticator::Krb5::Keytab.default.should.be a_keytab
    end
  end

  describe 'when I try to resolve a Keytab with a type of FILE and a path' do
    it 'must return a Keytab with that name' do
      KerberosAuthenticator::Krb5::Keytab.new_with_name('FILE:/etc/krb5.keytab').name.should.match /\/etc\/krb5.keytab$/
      #It should EQUAL 'FILE:/etc/krb5.keytab' but not all Kerberos implementations seem to do this.
    end
  end

  describe 'when I try to resolve a Keytab with a type of FILE and a non-ASCII path' do
    it 'must return a Keytab with that name' do
      KerberosAuthenticator::Krb5::Keytab.new_with_name('FILE:/итд/krb5.keytab').name.should.match /\/итд\/krb5.keytab$/
    end
  end

  describe 'when I try to resolve a Keytab with a nonsensical type' do
    it 'must raise an Error' do
      -> { KerberosAuthenticator::Krb5::Keytab.new_with_name('DOJO:講道館') }.should.raise KerberosAuthenticator::Krb5::Error
    end
  end

end
