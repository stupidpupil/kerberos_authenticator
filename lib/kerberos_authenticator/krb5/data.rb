module KerberosAuthenticator
  module Krb5
    attach_function :krb5_free_data_contents, [:krb5_context, :pointer], :void

    # Generic Kerberos library data structure.
    # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/types/krb5_data.html krb5_data
    class Data < FFI::Struct
      layout :magic, :krb5_error_code, :length, :int, :data_ptr, :pointer

      # Allocate and zero a new krb5_data struct or cast some existing memory to one.
      # @param pointer [Pointer] a pointer to existing memory to cast to a krb5_data struct
      # @see https://github.com/ffi/ffi/wiki/Structs Structs
      def initialize(pointer = nil)
        super(pointer)
        ObjectSpace.define_finalizer(self, self.class.finalize(self.pointer))
        self
      end

      # Read the data into a string.
      # @return [String]
      def read_string
        return "" if self[:length].zero?
        self[:data_ptr].read_bytes(self[:length])
      end

      # Builds a Proc to free the contents of the data structure once it's no longer in use.
      # @api private
      # return [Proc]
      def self.finalize(pointer)
        proc { Krb5.free_data_contents(Context.context.ptr, pointer); pointer.free}
      end

    end
  end
end