module KerberosAuthenticator
  module Krb5
    typedef :int, :krb5_error_code
    attach_function :krb5_get_error_message, [:pointer, :krb5_error_code], :strptr
    attach_function :krb5_free_error_message, [:pointer, :pointer], :void

    # A Kerberos library error
    class Error < StandardError
      attr_reader :error_code

      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_get_error_message.html krb5_get_error_message
      def initialize(context_ptr, krb5_error_code)
        @error_code = krb5_error_code
        error_message, error_ptr = Krb5.get_error_message(context_ptr, krb5_error_code)
        FFI::AutoPointer.new(error_ptr, self.class.finalize(context_ptr))
        super(String.new(error_message))
      end

      def self.finalize(context_ptr)
        proc { |ptr| Krb5.free_error_message(context_ptr, ptr) }
      end

      def self.raise_if_error(context_ptr = nil)
        err = yield
        return 0 if err == 0
        raise Krb5::Error.new(context_ptr, err)
      end
    end
  end
end
