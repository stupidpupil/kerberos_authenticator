module Devise
  module Strategies
    # An example Authentication Strategy for Devise (https://github.com/plataformatec/devise)
    #
    # It assumes that:
    # - the User resource responds to #kerberos_principal
    #   (implemented by transformation of the email address,
    #    or stored in the database, or by LDAP lookup, for example)
    #
    # - that if the User doesn't have a principal, then other strategies, like
    #   authenticating against a local database, might be valid
    class Kerberos < Authenticatable
      def valid?
        params['user']
      end

      def authenticate!
        resource = mapping.to.where(email: params['user']['email']).first
        raise(:not_found_in_database) and return unless validate(resource)

        principal = resource.kerberos_principal
        raise(:no_kerberos_principal_for_resource) and return unless principal

        begin
          success!(resource) if KerberosAuthenticator.authenticate!(principal, params['user']['password'])
        rescue KerberosAuthenticator::Error
          fail!(:invalid)
        end
      end
    end
  end
end
