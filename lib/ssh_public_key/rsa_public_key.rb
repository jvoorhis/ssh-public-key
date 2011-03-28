require 'ssh_public_key/blob_reader'
require 'ssh_public_key/blob_writer'

module SSHPublicKey
  class RSAPublicKey
    def self.parse(text)
      plaintext_sigil, blob, comment = text.split(/\s/)
      bytes = blob.unpack("m").first
      sigil, e, m = BlobReader.new(bytes).read_string.
                                          read_bigint.
                                          read_bigint.values
      new(:e => e, :m => m, :comment => comment)
    end

    attr_reader :e, :m, :comment

    def initialize(params)
      @e       = params[:e]
      @m       = params[:m]
      @comment = params[:comment]
    end

    def algorithm
      'RSA'
    end

    def sigil
      'ssh-rsa'
    end

    def blob
      bytes = BlobWriter.new.write_string(sigil).
                             write_bigint(e).
                             write_bigint(m).to_s
      [bytes].pack("m").tr("\n", "")
    end

    def to_s
      [sigil, blob, comment].join(" ")
    end
  end
end
