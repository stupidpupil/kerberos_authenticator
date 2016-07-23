# This spec can test integration if you have Kerberos configured
# and a principal with a password that you can use.
#
# The following environmental variables must be set:
# - KA_SPEC_SERVER - server principal to use
# - KA_SPEC_KEYTAB - Base64 encoded keytab for the server principal
# - KA_SPEC_FAULTY_KEYTAB - Base64 encoded keytab for the server principal, *but* not a valid one
# - KA_SPEC_USERNAME - username to use
# - KA_SPEC_PASSWORD - password to use
# - KA_SPEC_RUN_INTEGRATION - must be set to something

describe KerberosAuthenticator do
  before do
    if ENV['KA_SPEC_KRB5_CONFIG']
      @krb5_config = Tempfile.new('ka_krb5_conf', encoding: 'UTF-8')
      @krb5_config.write(Base64.decode64(ENV['KA_SPEC_KRB5_CONFIG']))
      @krb5_config.close

      ENV['KRB5_CONFIG'] = @krb5_config.path
    end

    if ENV['KA_SPEC_KEYTAB']
      @keytab = Tempfile.new('krb5_kt', encoding: 'binary')
      @keytab.write(Base64.decode64(ENV['KA_SPEC_KEYTAB']))
      @keytab.close

      ENV['KA_SPEC_KT_PATH'] = @keytab.path
    end

    KerberosAuthenticator.setup do |config|
      config.server = ENV['KA_SPEC_SERVER']
      config.keytab_base64 = nil
      config.keytab_path = ENV['KA_SPEC_KT_PATH']
      config.krb5.use_secure_context = false
    end

    @username = ENV['KA_SPEC_USERNAME']
    @password = ENV['KA_SPEC_PASSWORD']
  end

  if ENV['KA_SPEC_RUN_INTEGRATION']
    describe 'when I try to authenticate with a valid username and password' do
      it 'must return true' do
        KerberosAuthenticator.authenticate!(@username, @password).should.equal true
      end
    end

    describe 'when I try to authenticate with an invalid username and password' do
      it 'must raise an Error' do
        -> { KerberosAuthenticator.authenticate!(@username, "not#{@password}") }.should.raise KerberosAuthenticator::Error
      end
    end

    describe 'when I set a Base64 encoded keytab string and try to authenticate with a valid username and password' do
      it 'must return true' do
        KerberosAuthenticator.keytab_base64 = ENV['KA_SPEC_KEYTAB']
        KerberosAuthenticator.authenticate!(@username, @password).should.equal true
      end
    end

    describe 'when I set a keytab that the KDC does not know and try to authenticate with an apparently valid username and password' do
      it 'must raise an Error' do
        KerberosAuthenticator.keytab_base64 = ENV['KA_SPEC_FAULTY_KEYTAB']
        -> { KerberosAuthenticator.authenticate!(@username, @password) }.should.raise KerberosAuthenticator::Error
      end
    end

    describe 'when I specify a server principal name for which I have no key and try to authenticate' do
      it 'must raise an Error' do
        KerberosAuthenticator.server = 'notaserver@NOTAREALM.FAIL'
        -> { KerberosAuthenticator.authenticate!(@username, @password) }.should.raise KerberosAuthenticator::Error
      end
    end

    describe 'when I try to change a password (to the same password) with a valid username and password' do
      it 'must return true' do
        p = KerberosAuthenticator.change_password!(@username, @password, @password).should.equal true
      end
    end

    describe 'when changing a password to an empty one with a valid username and password' do
      it 'must raise an Error' do
        -> { KerberosAuthenticator.change_password!(@username, @password, '') }.should.raise StandardError
      end
    end

    describe 'when changing a password with an invalid username and password' do
      it 'must raise an Error' do
        -> { KKerberosAuthenticator.change_password!(@username, "not#{@password}", @password) }.should.raise StandardError
      end
    end

  end

  describe 'when I specify a username with a realm for which I know no KDCs' do
    it 'must raise an Error' do
      -> { KerberosAuthenticator.authenticate!('notauser@NOTREALM.FAIL', 'notapass') }.should.raise KerberosAuthenticator::Error
    end
  end
end
