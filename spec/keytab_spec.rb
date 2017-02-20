# Run some basic specs on Krb5::Keytab to check that:
# - the FFI interface can load the library and call functions
# - the error handling in the FFI interface is working
describe KerberosAuthenticator::Krb5::Keytab do
  before do
    if ENV['KA_SPEC_KEYTAB']
      keytab = Tempfile.new('krb5_kt', encoding: 'binary')
      keytab.write(Base64.decode64(ENV['KA_SPEC_KEYTAB']))
      keytab.close

      ENV['KA_SPEC_KT_PATH'] = keytab.path
    end

    @keytab_path = ENV['KA_SPEC_KT_PATH']
  end

  describe 'when I try to resolve the default Keytab' do
    it 'must return a Keytab' do
      a_keytab = lambda { |obj| obj.is_a?(KerberosAuthenticator::Krb5::Keytab) }
      KerberosAuthenticator::Krb5::Keytab.default.should.be a_keytab
    end
  end

  describe 'when I try to resolve a Keytab with a type of FILE and a path' do
    it 'must return a Keytab with that type and path' do
      kt = KerberosAuthenticator::Krb5::Keytab.new_with_name('FILE:/etc/krb5.keytab')
      kt.type.should.equal 'FILE'
      kt.path.should.equal '/etc/krb5.keytab'
    end
  end

  describe 'when I try to resolve a Keytab with a type of FILE and a fairly long path' do
    it 'must return a Keytab with that type and path' do
      kt = KerberosAuthenticator::Krb5::Keytab.new_with_name('FILE:'+('a'*300))
      kt.type.should.equal 'FILE'
      kt.path.should.equal ('a'*300)
    end
  end

  describe 'when I try to resolve a Keytab with a type of FILE and a non-ASCII path' do
    it 'must return a Keytab with that type and path' do
      kt = KerberosAuthenticator::Krb5::Keytab.new_with_name('FILE:/итд/krb5.keytab')
      kt.type.should.equal 'FILE'
      kt.path.should.equal '/итд/krb5.keytab'
    end
  end

  describe 'when I try to check the contents of a Keytab that does not exist' do
    it 'must return false' do
      kt = KerberosAuthenticator::Krb5::Keytab.new_with_name('FILE:./does/not/exist.keytab')
      kt.has_content?.should.equal false
    end
  end

  if ENV['KA_SPEC_KT_PATH']
    describe 'when I try to check the contents of a Keytab that does exist and contain entries' do
      it 'must return true' do
        kt = KerberosAuthenticator::Krb5::Keytab.new_with_name("FILE:#{@keytab_path}")
        kt.has_content?.should.equal true
      end
    end
  end

  describe 'when I try to resolve a Keytab with a nonsensical type' do
    it 'must raise an Error' do
      -> { KerberosAuthenticator::Krb5::Keytab.new_with_name('DOJO:講道館') }.should.raise KerberosAuthenticator::Krb5::Error
    end
  end
end
