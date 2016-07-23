module KerberosAuthenticator
  module Krb5
    typedef :int, :krb5_error_code
    attach_function :krb5_get_error_message, [:pointer, :krb5_error_code], :strptr
    attach_function :krb5_free_error_message, [:pointer, :pointer], :void

    # Generic exception class
    class Error < StandardError; end

    # A Kerberos error returned from a library call as a `krb5_error_code`.
    class LibCallError < Error
      # @!attribute [r] error_code
      #   @return [Integer] the krb5_error_code used to convey the status of a Kerberos library operation.
      #   @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/types/krb5_error_code.html krb5_error_code

      attr_reader :error_code

      # Initializes a new Error using an error code and the relevant Context to provide a friendly error message.
      # @param context_ptr [FFI::Pointer] A Context's pointer
      # @param krb5_error_code [Integer] An integer used to convey a operation's status
      # @return [Error]
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_get_error_message.html krb5_get_error_message
      def initialize(context_ptr, krb5_error_code)
        @error_code = krb5_error_code
        error_message, error_ptr = Krb5.get_error_message(context_ptr, krb5_error_code)
        FFI::AutoPointer.new(error_ptr, self.class.finalize(context_ptr))
        super(String.new(error_message))
      end

      # Build a Proc to free the error message string once it's no longer in use.
      # @api private
      # @return [Proc]
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_free_error_message.html krb5_free_error_message
      def self.finalize(context_ptr)
        proc { |ptr| Krb5.free_error_message(context_ptr, ptr) }
      end

      # Used to wrap Kerberos library functions that return a krb5_error_code.
      # @return [Integer] always returns zero on success
      # @yield [] A call to a Kerberos library function
      # @yieldreturn [Integer] a krb5_error_code
      # @raise [Error] if the krb5_error_code differed from zero
      def self.raise_if_error(context_ptr = nil)
        err = yield
        return 0 if err == 0
        raise self.new(context_ptr, err)
      end
    end

    # An error indicating a failure response from a server
    # when trying to change a password.
    # @see https://www.ietf.org/rfc/rfc3244.txt RFC 3244
    class SetPassError < Error
      # @!attribute [r] result_code
      #   @return [Integer] the result code used to convey the result of a Set Password operation.

      attr_reader :result_code

      # @!attribute [r] result_string
      #   @return [String] the full result string used to convey the result of a Set Password operation.

      attr_reader :result_string

      def initialize(result_code, result_string)
        @result_code = result_code
        @result_string = result_string
        super(result_string.lines.first)
      end
    end

  end
end
