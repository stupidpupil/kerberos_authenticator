module KerberosAuthenticator
  module Krb5
    typedef :pointer, :krb5_keytab

    attach_function :krb5_kt_resolve, [:krb5_context, :string, :pointer], :krb5_error_code
    attach_function :krb5_kt_default, [:krb5_context, :pointer], :krb5_error_code

    attach_function :krb5_kt_close, [:krb5_context, :krb5_keytab], :krb5_error_code

    begin
      # Heimdal
      attach_function :krb5_kt_get_full_name, [:krb5_context, :krb5_keytab, :pointer], :krb5_error_code
    rescue FFI::NotFoundError
      # MIT
      attach_function :krb5_kt_get_name, [:krb5_context, :krb5_keytab, :buffer_out, :int], :krb5_error_code
    end

    begin
      attach_function :krb5_kt_have_content, [:krb5_context, :krb5_keytab], :krb5_error_code
    rescue FFI::NotFoundError
      # REVIEW: Then we're probably using an old version of the library that doesn't support kt_have_content.
    end

    # Storage for locally-stored keys.
    class Keytab
      # @!attribute [r] ptr
      #   @return [FFI::Pointer] the pointer to the wrapped krb5_keytab struct


      attr_reader :ptr

      # Resolves a keytab identified by name.
      # The keytab is not opened and may not be accessible or contain any entries. (Use #has_content? to check.)
      # @param name [String] a name of the form 'type:residual', where usually type is 'FILE' and residual the path to that file
      # @raise [Error] if the type is unknown
      # @return [Keytab] a resolved, but not opened, keytab
      # @see http://web.mit.edu/Kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_resolve.html krb5_kt_resolve
      def self.new_with_name(name)
        pointer = FFI::MemoryPointer.new :pointer
        Krb5.kt_resolve(Context.context.ptr, name, pointer)

        new(pointer)
      end

      # Resolves the default keytab, usually the file at `/etc/krb5.keytab`.
      # The keytab is not opened and may not be accessible or contain any entries. (Use #has_content? to check.)
      # @return [Keytab] the default keytab
      # @see http://web.mit.edu/Kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_default.html krb5_kt_default
      def self.default
        pointer = FFI::MemoryPointer.new :pointer
        Krb5.kt_default(Context.context.ptr, pointer)

        new(pointer)
      end

      # Initializes a new Keytab with a pointer to a pointer to a krb5_keytab structure.
      # @param pointer [FFI::Buffer]
      # @return [Keytab]
      def initialize(pointer)
        @ptr = FFI::AutoPointer.new pointer.get_pointer(0), self.class.method(:release)

        self
      end

      # Checks if the underlying keytab file or other store exists and contains entries.
      # (When `krb5_kt_have_content` isn't provided by the Kerberos library, then only some very limited checks are performed.)
      # @return [TrueClass] if the keytab exists and contains entries
      # @raise [Error] if there is a problem finding entries in the keytab
      # @see http://web.mit.edu/Kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_have_content.html krb5_kt_have_content
      def assert_has_content
        if defined?(Krb5.kt_have_content)
          Krb5.kt_have_content(Context.context.ptr, ptr)
        else # HACK
          raise Error, "Could not read #{name}" if file? and !FileTest.readable?(path)
        end
        true
      end

      # @return [Boolean] whether the keytab exists and contains entries
      # @see #assert_has_content
      def has_content?
        assert_has_content
        true
      rescue Error
        false
      end

      # The maximum length, in bytes, that can be read by #name .
      GET_NAME_MAX_LENGTH = 512

      # The seperator between the type and the residual in a keytab's name
      FULL_NAME_DELIMITER = ':'

      # @return [String] the name of the key table
      # @see http://web.mit.edu/Kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_get_name.html kt_get_name
      def name
        if defined?(Krb5.kt_get_full_name)
          pointer = FFI::MemoryPointer.new :pointer
          Krb5.kt_get_full_name(Context.context.ptr, ptr, pointer)
          pointer = pointer.read_pointer
          copy = String.new(pointer.read_string).force_encoding('UTF-8')
          Krb5.xfree(pointer)
          copy
        else
          buffer = FFI::Buffer.new :char, GET_NAME_MAX_LENGTH
          Krb5.kt_get_name(Context.context.ptr, ptr, buffer, GET_NAME_MAX_LENGTH)
          buffer.read_bytes(255).force_encoding('UTF-8').split("\x00", 2)[0]
        end
      end

      # @return [String] the type of the key table
      def type
        name.split(FULL_NAME_DELIMITER, 2).first
      end

      # @return [String] the residual of the key table, which means different things depending on the type
      def residual
        name.split(FULL_NAME_DELIMITER, 2).last
      end

      # @return [Boolean] if the keytab has a type of 'FILE' or 'file'
      def file?
        type =~ /^FILE$/i
      end

      # @return [String, nil] the path to the keytab file if the keytab is a file, nil otherwise
      def path
        file? ? residual : nil
      end

      # Closes a Keytab
      # @api private
      # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/refs/api/krb5_kt_close.html krb5_kt_close
      def self.release(pointer)
        Krb5.kt_close(Context.context.ptr, pointer)
      end
    end
  end
end
