module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_keytab

    attach_function :krb5_kt_resolve, [:krb5_context, :string, :buffer_out], :krb5_error_code
    attach_function :krb5_kt_close, [:krb5_context, :krb5_keytab], :krb5_error_code
    attach_function :krb5_kt_get_type, [:krb5_context, :krb5_keytab], :string

    # Storage for locally-stored keys.
    class Keytab
      attr_reader :context

      # @param name [String] a name of the form 'type:residual', where usually type is 'FILE' and residual the path to that file
      # @return [Keytab]
      # @see http://web.mit.edu/Kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_resolve.html krb5_kt_resolve
      def self.new_with_name(name, context = Context.context)
        buffer = FFI::Buffer.new :pointer
        Krb5.kt_resolve(context.ptr, name, buffer)

        new(context, buffer)
      end

      # Initialize a new Keytab with a buffer containing a krb5_keytab structure, and define its finalizer.
      # @param context [Context]
      # @param buffer [FFI::Buffer]
      # @return [Keytab]
      def initialize(context, buffer)
        @context = context
        @buffer = buffer

        ObjectSpace.define_finalizer(self, self.class.finalize(context, buffer))
        self
      end

      # @return [FFI::Pointer] the pointer to the krb5_keytab structure
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/types/krb5_keytab.html krb5_keytab
      def ptr
        @buffer.get_pointer(0)
      end

      # @return [String] the type of the key table
      # @see http://web.mit.edu/Kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_get_type.html kt_get_type
      def type
        Krb5.kt_get_type(context.ptr, ptr)
      end

      # @api private
      def self.finalize(context, buffer)
        proc { Krb5.kt_close(context.ptr, buffer.get_pointer(0)) }
      end
    end
  end
end
