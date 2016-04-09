
This library is intended to make it easy to authenticate someone using their Kerberos username and password.

It uses [Ruby-FFI](https://github.com/ffi/ffi/) to call the Kerberos 5 library. I have tested it with the [Heimdal](https://www.h5l.org/) libary under OS X and the [MIT](http://web.mit.edu/kerberos/krb5-1.14/doc/) library under Debian.

# Example

You will need to have 1) [configured Kerberos correctly](http://web.mit.edu/kerberos/krb5-1.14/doc/admin/install_kdc.html#edit-kdc-configuration-files), and 2) obtained a service (or machine principal) and a keytab for that principal.

```ruby
require 'kerberos_authenticator'

KerberosAuthenticator.setup do |config|
  # Information for the Kerberos 5 library passed through environmental variables is ignored by default.
  # (See http://web.mit.edu/kerberos/krb5-current/doc/admins/env_variables.html)
  # If you want to use these environmental variables, uncomment the line below.
  # config.krb5.use_secure_context = false

  # The authenticator requests ticket-granting-tickets (TGTs) by default.
  # You can request tickets for a specific service by editing the line below.
  # config.service = 'service@EXAMPLE.ORG'

  # Configure the server principal and keytab used to verify the credentials received from the KDC.
  # Setting these to nil will let the underlying Kerberos 5 library try its own defaults.
  config.server = 'server@EXAMPLE.ORG'
  config.keytab_path = 'example.keytab'

  # Provide a keytab as a Base64 encoded string (e.g from an enviromental variable).
  # This will override keytab_path.
  # config.keytab_base64 = Base64.encode64(File.read('example.keytab'))
end

begin
  KerberosAuthenticator.authenticate!('user@EXAMPLE.ORG', 'mypassword')
  puts 'Successful authentication!'
rescue KerberosAuthenticator::Error => e
  puts 'Failed to authenticate!'
  puts e.inspect
end
```

# Zanarotti attack
*(Or why do I need a keytab?)*

Getting credentials from a Kerberos Domain Controller (KDC) for a given username and password isn't sufficient to authenticate a user. This is because an attacker might be able to trick your server into obtaining credentials from a malicious KDC (by DNS hijacking, for example). This attack is called the Zanarotti attack (after [Stan Zanarotti](http://www.mit.edu/people/srz/home.html)).

In order to avoid the Zanarotti attack, your application has to confirm the identity of the KDC that provided credentials for your user. A service principal's key (stored in a keytab) provides one way of doing this - the key is a secret shared only between your application and the KDC.

You can read more about this in the [MIT Kerberos documentation](http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/init_creds.html). 

I wrote this gem specifically because most Ruby examples of using Kerberos to authenticate a user with their username and password failed to verify the identity of the KDC. Most Ruby interfaces to Kerberos 5 libraries did not even support the `krb5_verify_init_creds` function necessary to implement this verification.

## Vulnerable Ruby examples
* https://github.com/atomaka/devise-kerberos-authenticatable
* https://github.com/naffis/omniauth-krb5
* https://github.com/sleeper/rack-auth-krb

# Issues

Crash under Heimdal when no server principal given (?!)
Permission denied when no keytab given (tries to  read /etc/krb5.keytab)
LoadError, can't find krb5 - `FFI_KRB5_LIBRARY_NAME`