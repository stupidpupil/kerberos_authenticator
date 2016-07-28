# Run some basic specs on Krb5::Context to check that:
# - the FFI interface can load the library and call functions
# - the error handling in the FFI interface is working
describe KerberosAuthenticator::Krb5::Context do
  describe 'when I call .context' do
    it 'must give me a thread-specific Context' do
      KerberosAuthenticator::Krb5::Context.context.should.equal KerberosAuthenticator::Krb5::Context.context

      other_ctx = nil
      thread = Thread.new { other_ctx = Context.context}

      KerberosAuthenticator::Krb5::Context.context.should.not.equal other_ctx
    end
  end

  describe 'when I ask for the default realm' do
    it 'must return the default realm' do
      ENV['KRB5_CONFIG'] = File.expand_path('krb5.conf', FIXTURES_DIR)
      KerberosAuthenticator::Krb5::Context.new(false).default_realm.should.equal 'EXAMPLE.ORG'
    end
  end
end