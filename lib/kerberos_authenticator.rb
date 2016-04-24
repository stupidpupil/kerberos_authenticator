require 'base64'
require 'tempfile'

require 'kerberos_authenticator/version'
require 'kerberos_authenticator/error'
require 'kerberos_authenticator/krb5'

module KerberosAuthenticator

  # A convenience method to access the Krb5 module when using the setup method.
  # @return [Krb5]
  def self.krb5
    Krb5
  end

  # Supports setting KerberosAuthenticator up using a block.
  def self.setup
    yield self
  end

  # Authenticates a user using their password.
  # @param username [String] a string representation of the user's principal
  # @param password [String] the user's password
  # @raise [Error] if Kerberos can't understand the principal or contact any KDCs for the principal's realm
  # @raise [Error] if preauthentication fails (usually meaning that the user's password was incorrect)
  # @raise [Error] if the KDC cannot find the user
  # @return [TrueClass] always returns true if authentication succeeds without any error
  # @see http://web.mit.edu/kerberos/krb5-1.14/doc/appdev/init_creds.html Initial credentials
  def self.authenticate!(username, password)
    user = Krb5::Principal.new_with_name(username)
    creds = user.initial_creds_with_password(password, service)

    with_keytab do |kt|
      creds.verify!(server_princ, kt)
    end

    true
  end

  # @!attribute [rw] server
  #   @return [String] the server principal name to use when verifying the identity of the KDC

  # @!attribute [rw] service
  #   @return [String] the service principal name to request a ticket for when obtaining a user's credentials

  # @!attribute [rw] keytab_base64
  #   @return [String] the keytab to use when verifying the identity of the KDC represented as a Base64 encoded string (overrides keytab_path)

  # @!attribute [rw] keytab_path
  #   @return [String] the path to the keytab to use when verifying the identity of the KDC

  @service = nil

  def self.service
    @service
  end

  def self.service=(v)
    @service = v
  end

  @server = nil

  def self.server
    @server
  end

  def self.server=(v)
    @server = v
  end

  @keytab_base64 = nil
  @keytab_path = nil

  def self.keytab_base64
    @keytab_base64
  end

  def self.keytab_base64=(v)
    @keytab_base64 = v
  end

  def self.keytab_path
    @keytab_path
  end

  def self.keytab_path=(v)
    @keytab_path = v
  end

  def self.server_princ
    server ? Krb5::Principal.new_with_name(server) : nil
  end

  def self.new_kt_tmp_file
    return nil unless keytab_base64

    kt_tmp_file = Tempfile.new('krb5_kt', encoding: 'binary')
    kt_tmp_file.write(Base64.decode64(keytab_base64))
    kt_tmp_file.close

    kt_tmp_file
  end

  def self.with_keytab
    if keytab_base64
      kt_tmp_file = new_kt_tmp_file
      kt = Krb5::Keytab.new_with_name("FILE:#{kt_tmp_file.path}")
    elsif keytab_path
      kt = Krb5::Keytab.new_with_name("FILE:#{keytab_path}")
    end

    begin
      yield kt
    ensure
      kt_tmp_file.close! if kt_tmp_file
    end
  end

  private_class_method :server_princ, :new_kt_tmp_file, :with_keytab
end
