module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_context

    attach_function :krb5_init_context, [:pointer], :krb5_error_code
    attach_function :krb5_free_context, [:krb5_context], :void

    begin
      attach_function :krb5_init_secure_context, [:pointer], :krb5_error_code
    rescue FFI::NotFoundError
      # Then we're probably using a version of the Heimdal library
      # that doesn't support init_secure_context (and ignores environmental variables by default)
      alias_method(:init_secure_context, :init_context)
      module_function :init_secure_context
    end

    attach_function :krb5_get_default_realm, [:krb5_context, :pointer], :krb5_error_code

    begin
      attach_function :krb5_xfree, [:pointer], :krb5_error_code
    rescue FFI::NotFoundError
      # MIT
    end

    begin
      attach_function :krb5_free_string, [:krb5_context, :pointer], :void
    rescue FFI::NotFoundError
      # Heimdal
      define_method(:free_string) { |_ctx, pointer| Krb5.xfree(pointer) }
      module_function :free_string
    end

    # A Kerberos context, holding all per-thread state.
    class Context
      # @!attribute [r] ptr
      #   @return [FFI::Pointer] the pointer to the wrapped krb5_context struct

      attr_reader :ptr

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
        pointer = FFI::MemoryPointer.new :pointer

        if secure
          Krb5::LibCallError.raise_if_error { Krb5.init_secure_context(pointer) }
        else
          Krb5::LibCallError.raise_if_error { Krb5.init_context(pointer) }
        end

        @ptr = FFI::AutoPointer.new pointer.get_pointer(0), self.class.method(:release)

        self
      end

      # Retrieves the default realm
      # @return [String]
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_get_default_realm.html krb5_get_default_realm
      def default_realm
        out_ptr = FFI::MemoryPointer.new :pointer
        Krb5.get_default_realm(ptr, out_ptr)

        str_ptr = out_ptr.read_pointer
        copy = String.new(str_ptr.read_string).force_encoding('UTF-8')

        Krb5.free_string(ptr, str_ptr)

        copy
      end

      # Frees a Context
      # @api private
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_free_context.html krb5_free_context
      def self.release(pointer)
        Krb5.free_context pointer
      end
    end
  end
end
