module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_creds

    attach_function :krb5_get_init_creds_password, [:krb5_context, :krb5_creds, :krb5_principal, :string, :pointer, :pointer, :int, :string, :pointer], :krb5_error_code
    attach_function :krb5_verify_init_creds, [:krb5_context, :krb5_creds, :krb5_principal, :pointer, :pointer, :pointer], :krb5_error_code

    attach_function :krb5_verify_init_creds_opt_init, [:pointer], :void
    attach_function :krb5_verify_init_creds_opt_set_ap_req_nofail, [:pointer, :bool], :void

    attach_function :krb5_free_cred_contents, [:krb5_context, :krb5_creds], :void
    attach_function :krb5_get_init_creds_opt_free, [:krb5_context, :pointer], :void

    # Credentials, or tickets, provided by a KDC for a user.
    class Creds
      attr_reader :context, :ptr

      # Requests initial credentials for principal using password from a KDC.
      # @param principal [Principal] the user's Principal
      # @param password [String] the user's password
      # @param service [String] the service name used when requesting the credentials
      # @return [Creds]
      # @raise [Error] if a KDC for the principal can't be contacted
      # @raise [Error] if preauthentication fails
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_get_init_creds_password.html krb5_get_init_creds_password
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/init_creds.html Initial credentials
      def self.initial_creds_for_principal_with_a_password(principal, password, service = nil)
        raise TypeError, 'expected Principal' unless principal.is_a? Principal

        context = principal.context
        ptr = FFI::MemoryPointer.new :char, 480 # HACK

        Krb5.get_init_creds_password(context.ptr, ptr, principal.ptr, password.to_str, nil, nil, 0, service, nil)

        new(context, ptr)
      end

      def initialize(context, ptr)
        @context = context
        @ptr = ptr

        @ptr.autorelease = false
        ObjectSpace.define_finalizer(self, self.class.finalize(context, ptr))

        self
      end

      # Calls #verify with nofail as true.
      # @see #verify
      def verify!(server_principal = nil, keytab = nil)
        verify(true, server_principal, keytab)
      end

      # Attempt to verify that these Creds were obtained from a KDC with knowledge of a key in keytab.
      # @param nofail [Boolean] whether to raise an Error if no keytab information is available
      # @param server_principal [Principal] the server principal to use choosing an entry in keytab
      # @param keytab [Keytab] the key table containing a key that the KDC should know
      # @raise [Error] if nofail is true and no keytab information is available
      # @raise [Error] if the KDC did not have knowledge of the key requested
      # @return [TrueClass] always returns true if no error was raised
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_verify_init_creds.html krb5_verify_init_creds
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_verify_init_creds_opt_set_ap_req_nofail.html krb5_verify_init_creds_opt_set_ap_req_nofail
      def verify(nofail = false, server_principal = nil, keytab = nil)
        verify_creds_opt = FFI::MemoryPointer.new :int, 2
        Krb5.verify_init_creds_opt_init(verify_creds_opt)
        Krb5.verify_init_creds_opt_set_ap_req_nofail(verify_creds_opt, nofail)

        server_princ_ptr = server_principal ? server_principal.ptr : nil
        keytab_ptr = keytab ? keytab.ptr : nil

        Krb5.verify_init_creds(context.ptr, ptr, server_princ_ptr, keytab_ptr, nil, verify_creds_opt)

        true
      end

      # @api private
      def self.finalize(context, ptr)
        proc { Krb5.free_cred_contents(context.ptr, ptr); ptr.free}
      end
    end
  end
end
