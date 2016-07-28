module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_creds

    attach_function :krb5_get_init_creds_password, [:krb5_context, :krb5_creds, :krb5_principal, :string, :pointer, :pointer, :int, :string, :pointer], :krb5_error_code
    attach_function :krb5_verify_init_creds, [:krb5_context, :krb5_creds, :krb5_principal, :pointer, :pointer, :pointer], :krb5_error_code

    attach_function :krb5_verify_init_creds_opt_init, [:pointer], :void
    attach_function :krb5_verify_init_creds_opt_set_ap_req_nofail, [:pointer, :bool], :void

    attach_function :krb5_free_cred_contents, [:krb5_context, :krb5_creds], :void
    attach_function :krb5_get_init_creds_opt_free, [:krb5_context, :pointer], :void

    attach_function :krb5_set_password, [:krb5_context, :krb5_creds, :string, :krb5_principal, :pointer, :pointer, :pointer], :krb5_error_code

    # Credentials, or tickets, provided by a KDC for a user.
    class Creds
      # @!attribute [r] ptr
      #   @return [FFI::Pointer] the pointer to the wrapped krb5_creds struct


      attr_reader :ptr

      # The size, in bytes, of the krb5_creds structure.
      # This differs between implementations and architectures.
      SIZE_OF_KRB5_CREDS = 480

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

        ptr = FFI::MemoryPointer.new :char, SIZE_OF_KRB5_CREDS
        Krb5.get_init_creds_password(Context.context.ptr, ptr, principal.ptr, password.to_str, nil, nil, 0, service, nil)

        new(ptr)
      end

      # Initialize a new Keytab with a pointer to a krb5_keytab structure.
      # @param ptr [FFI::MemoryPointer]
      # @return [Keytab]
      def initialize(ptr)
        # HACK: AutoPointer won't accept a MemoryPointer, only a Pointer
        ptr.autorelease = false
        ptr = FFI::Pointer.new(ptr)

        ptr = FFI::AutoPointer.new ptr, self.class.method(:release)

        @ptr = ptr
      end

      # Calls #verify with nofail as true.
      # @see #verify
      def verify!(server_principal = nil, keytab = nil)
        verify(true, server_principal, keytab)
      end

      # Attempts to verify that these Creds were obtained from a KDC with knowledge of a key in keytab.
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

        Krb5.verify_init_creds(Context.context.ptr, ptr, server_princ_ptr, keytab_ptr, nil, verify_creds_opt)

        true
      end

      # Sets a password for a principal using these Creds.
      # The Creds should be for the 'kadmin/changepw' service.
      # @param newpw [String] the new password
      # @param change_password_for [Principal] the Principal to change the password for
      # @raise [Error] if there is a problem making the password change request
      # @raise [Error] if server responds that the password change request failed
      # @return [TrueClass] always returns true if no error was raised
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_set_password.html krb5_set_password
      def set_password(newpw, change_password_for = nil)
        change_password_for_ptr = change_password_for ? change_password_for.ptr : nil

        result_code = FFI::MemoryPointer.new :int
        result_code_string = Data.new
        result_string = Data.new

        Krb5.set_password(Context.context.ptr, ptr, newpw, change_password_for_ptr, result_code, result_code_string.pointer, result_string.pointer)

        result_code = result_code.read_uint
        result_string = result_string.read_string.force_encoding('UTF-8')
        raise SetPassError.new(result_code, result_string) if result_code > 0

        true
      end

      # Frees the contents of the Creds structure
      # @api private
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_free_cred_contents.html krb5_free_cred_contents
      def self.release(pointer)
        Krb5.free_cred_contents(Context.context.ptr, pointer)
      end
    end
  end
end
