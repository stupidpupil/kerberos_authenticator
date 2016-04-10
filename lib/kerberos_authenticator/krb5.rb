require 'ffi'

module KerberosAuthenticator
  # An FFI wrapper around the Kerberos 5 library.
  # Use the environmental variable FFI_KRB5_LIBRARY_NAME to override the library loaded.
  module Krb5
    extend FFI::Library

    PREFERRED_VERSIONS = ['.3','.26','']

    if ENV['FFI_KRB5_LIBRARY_NAME']
      ffi_lib ENV['FFI_KRB5_LIBRARY_NAME']
    else
      ffi_lib PREFERRED_VERSIONS.map {|v| FFI.map_library_name('krb5') + v}
    end

    # @!attribute [rw] use_secure_context
    #   @return [Boolean] if Context.context should ignore environmental variables when returning a library context

    @use_secure_context = true

    def self.use_secure_context
      @use_secure_context
    end

    def self.use_secure_context=(v)
      @use_secure_context = v
    end
  end
end

require 'kerberos_authenticator/krb5/attach_function'
require 'kerberos_authenticator/krb5/error'
require 'kerberos_authenticator/krb5/context'
require 'kerberos_authenticator/krb5/principal'
require 'kerberos_authenticator/krb5/creds'
require 'kerberos_authenticator/krb5/keytab'
