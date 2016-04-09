module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_principal

    attach_function :krb5_parse_name, [:krb5_context, :string, :krb5_principal], :krb5_error_code
    attach_function :krb5_free_principal, [:krb5_context, :krb5_principal], :void

    attach_function :krb5_unparse_name, [:krb5_context, :krb5_principal, :pointer], :krb5_error_code
    attach_function :krb5_free_unparsed_name, [:krb5_context, :pointer], :void

    # A Kerberos principal identifying a user, service or machine.
    class Principal
      attr_reader :context

      # Convert a string representation of a principal name into a new Principal.
      # @param name [String] a string representation of a principal name
      # @param context [Context] a Kerberos library context
      # @return [Principal]
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_parse_name.html krb5_parse_name
      def self.new_with_name(name, context = Context.context)
        raise ArgumentError, 'name cannot be empty' if name.empty?

        buffer = FFI::Buffer.new :pointer
        Krb5.parse_name(context.ptr, name, buffer)
        new(context, buffer)
      end

      def initialize(context, buffer)
        @context = context
        @buffer = buffer

        ObjectSpace.define_finalizer(self, self.class.finalize(context, buffer))

        self
      end

      # @param password [String]
      # @param service [String]
      # @return [Creds]
      # @see Creds.initial_creds_for_principal_with_a_password
      def initial_creds_with_password(password, service = nil)
        Creds.initial_creds_for_principal_with_a_password(self, password, service)
      end

      def ptr
        @buffer.get_pointer(0)
      end

      # @return [String] a string representation of the principal's name
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_unparse_name.html krb5_unparse_name
      def name
        out_ptr = FFI::MemoryPointer.new(:pointer, 1)
        Krb5.unparse_name(context.ptr, ptr, out_ptr)

        str_ptr = out_ptr.read_pointer
        copy = String.new(str_ptr.read_string)

        Krb5.free_unparsed_name(context.ptr, str_ptr)

        copy
      end

      # @api private
      def self.finalize(context, buffer)
        proc { Krb5.free_principal(context.ptr, buffer.get_pointer(0)) }
      end
    end
  end
end
