module KerberosAuthenticator
  module Krb5
    attach_function :krb5_free_data_contents, [:krb5_context, :pointer], :void

    # Generic Kerberos library data structure.
    # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/types/krb5_data.html krb5_data
    class Data < FFI::ManagedStruct
      layout :magic, :krb5_error_code, :length, :int, :data_ptr, :pointer

      # Allocates and zeroes a new krb5_data struct or cast some existing memory to one.
      # @param pointer [Pointer] a pointer to existing memory to cast to a krb5_data struct
      # @see https://github.com/ffi/ffi/wiki/Structs Structs
      def initialize(pointer = nil)
        unless pointer
          pointer = FFI::MemoryPointer.new :char, self.class.size

          # HACK: AutoPointer won't accept a MemoryPointer, only a Pointer
          pointer.autorelease = false
          pointer = FFI::Pointer.new(pointer)
        end

        super(pointer)
      end

      # Reads the data into a string.
      # @return [String]
      def read_string
        return '' if self[:length].zero?
        self[:data_ptr].read_bytes(self[:length])
      end

      # Frees the contents of a Data struct 
      # @api private
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_free_data_contents.html krb5_free_data_contents
      def self.release(pointer)
        Krb5.free_data_contents(Context.context.ptr, pointer)
      end
    end
  end
end
