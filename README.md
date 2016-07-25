# Kerberos Authenticator
[![Build Status](https://travis-ci.org/stupidpupil/kerberos_authenticator.svg?branch=master)](https://travis-ci.org/stupidpupil/kerberos_authenticator)
[![Code Climate](https://codeclimate.com/github/stupidpupil/kerberos_authenticator/badges/gpa.svg)](https://codeclimate.com/github/stupidpupil/kerberos_authenticator)
[![Test Coverage](https://codeclimate.com/github/stupidpupil/kerberos_authenticator/badges/coverage.svg)](https://codeclimate.com/github/stupidpupil/kerberos_authenticator/coverage)
[![Docs](http://inch-ci.org/github/stupidpupil/kerberos_authenticator.svg?branch=master&style=shields)](http://www.rubydoc.info/github/stupidpupil/kerberos_authenticator)
[![Gem](https://img.shields.io/gem/v/kerberos_authenticator.svg?maxAge=2592000)](https://rubygems.org/gems/kerberos_authenticator)


This library is intended to make it easy to authenticate someone using their Kerberos password in your Ruby application.

It uses [Ruby-FFI](https://github.com/ffi/ffi/) to call the Kerberos 5 library. I have tested it with the Kerberos library included with Mac OS X, and with the latest MIT and Heimdal libraries under Debian. ([Tests on Travis](https://travis-ci.org/stupidpupil/kerberos_authenticator) are run using the MIT library.)

## Example

You will need to have 
  1. [configured Kerberos correctly](http://web.mit.edu/kerberos/krb5-1.14/doc/admin/install_kdc.html#edit-kdc-configuration-files), and 
  2. obtained a service (or machine principal) and a keytab for that principal.

```ruby
require 'kerberos_authenticator'

KerberosAuthenticator.setup do |config|
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

# You can change passwords too.
KerberosAuthenticator.change_password!('user@EXAMPLE.ORG', 'mypassword', 'my_new_password')
```

## Zanarotti attack
*(Or why do I need a keytab?)*

Getting credentials from a Kerberos Domain Controller (KDC) for a given username and password isn't sufficient to authenticate a user. This is because an attacker might be able to trick your server into obtaining credentials from a malicious KDC (by DNS hijacking, for example). This attack is called the Zanarotti attack (after [Stan Zanarotti](http://www.mit.edu/people/srz/home.html)).

In order to avoid the Zanarotti attack, your application has to confirm the identity of the KDC that provided credentials for your user. A service principal's key (stored in a keytab) provides one way of doing this - the key is a secret shared only between your application and the KDC.

You can read more about this in the [MIT Kerberos documentation](http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/init_creds.html). 

I wrote this gem specifically because existing Ruby examples of using Kerberos to authenticate a user with their username and password failed to verify the identity of the KDC, and existing Ruby interfaces to Kerberos 5 libraries did not support the `krb5_verify_init_creds` function necessary to implement this verification.

## Thread safety and Memory leaks
I believe that, when used with a recent version of the MIT Kerberos library, this gem is both thread-safe and free of memory leaks. Please do report any issues that you find.

## LoadError
If requiring the gem results in a LoadError, you can specify how to find your Kerberos 5 library by setting the `FFI_KRB5_LIBRARY_NAME` environmental variable. (Or you could install the development files for your Kerberos 5 library, which should almost always allow the gem to find the library.)

## License
This gem is licensed under the [MIT License](http://choosealicense.com/licenses/mit/).
