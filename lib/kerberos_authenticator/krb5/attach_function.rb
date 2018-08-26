module KerberosAuthenticator
  module Krb5
    # Attaches a Kerberos library function to {Krb5}.
    # Extends FFI's built-in method to:
    # - drop the krb5_ prefix from function names
    # - wrap any call returning a krb5_error_code with {Krb5::LibCallError.raise_if_error}
    # @api private
    # @see http://www.rubydoc.info/github/ffi/ffi/FFI/Library#attach_function-instance_method FFI::Library#attach_function
    def self.attach_function(c_name, params, returns, options = {})
      ruby_name = c_name.to_s.gsub(/^krb5_/, '').to_sym

      super(ruby_name, c_name, params, returns, options)

      if returns == :krb5_error_code
        no_check_name = "#{ruby_name}_without_catching_error"

        alias_method(no_check_name, ruby_name)

        if params.first == :krb5_context
          define_method(ruby_name) do |*args, &block|
            Krb5::LibCallError.raise_if_error(args.first) { public_send(no_check_name, *args, &block) }
          end
        else
          define_method(ruby_name) do |*args, &block|
            Krb5::LibCallError.raise_if_error(nil) { public_send(no_check_name, *args, &block) }
          end
        end

        module_function no_check_name
      end

      module_function ruby_name
    end
  end
end
