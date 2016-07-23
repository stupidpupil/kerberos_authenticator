module KerberosAuthenticator
  module Krb5
    attach_function :krb5_free_data_contents, [:krb5_context, :pointer], :void

    # Generic Kerberos library data structure.
    # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/types/krb5_data.html krb5_data
    class Data < FFI::Struct
      layout :magic, :krb5_error_code, :length, :int, :data_ptr, :pointer

      def initialize(*args)
        super(*args)
        ObjectSpace.define_finalizer(self, self.class.finalize(self.pointer))
      end

      # Read the data into a string.
      # @return [String]
      def read_string
        self[:data_ptr].read_string_length(self[:length])
      end

      # Builds a Proc to free the contents of the data structure once it's no longer in use.
      # @api private
      # return [Proc]
      def self.finalize(pointer)
        proc { Krb5.free_data_contents(Context.context.ptr, pointer) }
      end

    end
  end
end