require 'twos_complement'
require 'ssh_public_key/rsa_public_key'
require 'ssh_public_key/dsa_public_key'

module SSHPublicKey

  module_function

  def parse(text)
    case text
    when /^ssh-rsa/ then RSAPublicKey.parse(text)
    when /^ssh-dss/ then DSAPublicKey.parse(text)
    end
  end
end
