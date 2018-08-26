module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_principal

    attach_function :krb5_parse_name, [:krb5_context, :string, :pointer], :krb5_error_code
    attach_function :krb5_free_principal, [:krb5_context, :krb5_principal], :void

    attach_function :krb5_unparse_name, [:krb5_context, :krb5_principal, :pointer], :krb5_error_code
    attach_function :krb5_free_unparsed_name, [:krb5_context, :pointer], :void

    # A Kerberos principal identifying a user, service or machine.
    class Principal
      # @!attribute [r] ptr
      #   @return [FFI::Pointer] the pointer to the wrapped krb5_principal struct


      attr_reader :ptr

      # Convert a string representation of a principal name into a new Principal.
      # @param name [String] a string representation of a principal name
      # @return [Principal]
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_parse_name.html krb5_parse_name
      def self.new_with_name(name)
        raise ArgumentError, 'name cannot be empty' if name.empty?

        pointer = FFI::MemoryPointer.new :pointer
        Krb5.parse_name(Context.context.ptr, name, pointer)
        new(pointer)
      end

      # Initialize a new Principal with a pointer to a pointer to a krb5_principal structure.
      # @param pointer [FFI::Pointer]
      # @return [Principal]
      def initialize(pointer)
        @ptr = FFI::AutoPointer.new pointer.get_pointer(0), self.class.method(:release)

        self
      end

      # Calls Creds.initial_creds_for_principal_with_a_password(self, password, service)
      # @param password [String]
      # @param service [String]
      # @return [Creds]
      # @see Creds.initial_creds_for_principal_with_a_password
      def initial_creds_with_password(password, service = nil)
        Creds.initial_creds_for_principal_with_a_password(self, password, service)
      end

      # @return [String] a string representation of the principal's name
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_unparse_name.html krb5_unparse_name
      def name
        out_ptr = FFI::MemoryPointer.new(:pointer, 1)
        Krb5.unparse_name(Context.context.ptr, ptr, out_ptr)

        str_ptr = out_ptr.read_pointer
        copy = String.new(str_ptr.read_string).force_encoding('UTF-8')

        Krb5.free_unparsed_name(Context.context.ptr, str_ptr)

        copy
      end

      alias :to_s :name

      # Returns true if other is also a Principal and it has the same name as this Principal.
      # @return [Boolean]
      def ==(other)
        (other.is_a? self.class) and (other.name == self.name)
      end

      alias :eql? :==

      # Generates an integer hash value for the Principal based on its name.
      # @return [Integer]
      def hash
        [self.class, self.name].hash
      end

      # Produces a human-readable representation of this Principal object, 
      # including the Principal's #name.
      # @return [String]
      def inspect
        "#<#{self.class.name} #{self.name}>"
      end

      # A convenience function to allow a Principal to change a password by authenticating themselves.
      # @raise [Error] if the attempt to change the password fails
      # @return [TrueClass] always returns true if no error was raised
      # @see Creds#set_password
      def change_password(oldpw, new_pw)
        changepw_creds = self.initial_creds_with_password(oldpw, 'kadmin/changepw')
        changepw_creds.set_password(new_pw, self)
      end

      # Frees a Principal
      # @api private
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_free_principal.html krb5_free_principal
      def self.release(pointer)
        Krb5.free_principal(Context.context.ptr, pointer)
      end
    end
  end
end
