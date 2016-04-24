module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_context

    attach_function :krb5_init_context, [:buffer_out], :krb5_error_code
    attach_function :krb5_free_context, [:krb5_context], :void

    begin
      attach_function :krb5_init_secure_context, [:buffer_out], :krb5_error_code
    rescue FFI::NotFoundError
      # Then we're probably using a version of the Heimdal library
      # that doesn't support init_secure_context (and ignore environmental variables by default)
      alias_method(:init_secure_context, :init_context)
      module_function :init_secure_context
    end

    # A Kerberos context, holding all per-thread state.
    class Context
      # @return [Context] a fibre-local Context
      def self.context
        if Krb5.use_secure_context
          Thread.current[:krb5_secure_context] ||= new(true)
        else
          Thread.current[:krb5_context] ||= new
        end
      end

      # @param secure [Boolean] whether to ignore environmental variables when constructing a library context
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_init_secure_context.html krb5_init_secure_context
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_init_context.html krb5_init_context
      def initialize(secure = false)
        @buffer = FFI::Buffer.new :pointer

        if secure
          Krb5::Error.raise_if_error { Krb5.init_secure_context(@buffer) }
        else
          Krb5::Error.raise_if_error { Krb5.init_context(@buffer) }
        end

        ObjectSpace.define_finalizer(self, self.class.finalize(@buffer))
        self
      end

      # @return [FFI::Pointer] the pointer to the krb5_context structure
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/types/krb5_context.html krb5_context
      def ptr
        @buffer.get_pointer(0)
      end

      # Builds a Proc to free the Context once its no longer in use.
      # @api private
      # @return [Proc]
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_free_context.html krb5_free_context
      def self.finalize(buffer)
        proc { Krb5.free_context(buffer.get_pointer(0)) }
      end
    end
  end
end
