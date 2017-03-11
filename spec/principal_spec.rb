# Run some basic specs on Krb5::Principal to check that:
# - the FFI interface can load the library and call functions
# - the error handling in the FFI interface is working
describe KerberosAuthenticator::Krb5::Principal do
  describe 'when I try to create a Principal with an invalid name' do
    it 'must raise an Error' do
      -> { KerberosAuthenticator::Krb5::Principal.new_with_name('name@realm@doubleReam') }.should.raise KerberosAuthenticator::Krb5::Error
    end
  end

  describe 'when I try to create a Principal with a valid name' do
    it 'must return a Principal with that name' do
      KerberosAuthenticator::Krb5::Principal.new_with_name('name@realm').name.should.equal 'name@realm'
    end
  end

  describe 'when I try to create a Principal with a non-ASCII valid name' do
    it 'must return a Principal with that name' do
      KerberosAuthenticator::Krb5::Principal.new_with_name('владимир@кремль.ру').name.should.equal 'владимир@кремль.ру'
    end
  end

  describe 'when I create two Principals with the same name and compare them' do
    it 'must return that they are equal' do
      a = KerberosAuthenticator::Krb5::Principal.new_with_name('владимир@кремль.ру')
      b = KerberosAuthenticator::Krb5::Principal.new_with_name('владимир@кремль.ру')

      a.should.equal b
      b.should.equal a

      a.hash.should.equal b.hash
    end
  end

  describe 'when I create two Principals with different names and compare them' do
    it 'must return that they are not equal' do
      a = KerberosAuthenticator::Krb5::Principal.new_with_name('владимир@кремль.ру')
      b = KerberosAuthenticator::Krb5::Principal.new_with_name('борис@кремль.ру')

      a.should.not.equal b
      b.should.not.equal a
    end
  end

end
