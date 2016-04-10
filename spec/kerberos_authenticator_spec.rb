# This spec can test integration if you have Kerberos configured
# and a principal with a password that you can use.
#
# The following environmental variables must be set:
# - KA_SPEC_SERVER - server principal to use
# - KA_SPEC_KT_PATH - path to keytab to use
# - KA_SPEC_USERNAME - username to use
# - KA_SPEC_PASSWORD - password to use
# - KA_SPEC_RUN_INTEGRATION - must be set to something

describe KerberosAuthenticator do
  before do
    KerberosAuthenticator.setup do |config|
      config.server = ENV['KA_SPEC_SERVER']
      config.keytab_path = ENV['KA_SPEC_KT_PATH']
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
        KerberosAuthenticator.keytab_base64 = Base64.encode64(File.read(ENV['KA_SPEC_KT_PATH']))
        KerberosAuthenticator.authenticate!(@username, @password).should.equal true
      end
    end

    describe 'when I specify a server principal name for which I have no key and try to authenticate' do
      it 'must raise an Error' do
        KerberosAuthenticator.server = 'notaserver@NOTAREALM.FAIL'
        -> { KerberosAuthenticator.authenticate!(@username, @password) }.should.raise KerberosAuthenticator::Error
      end
    end
  end

  describe 'when I specify a username with a realm for which I know no KDCs' do
    it 'must raise an Error' do
      -> { KerberosAuthenticator.authenticate!('notauser@NOTREALM.FAIL', 'notapass') }.should.raise KerberosAuthenticator::Error
    end
  end
end
