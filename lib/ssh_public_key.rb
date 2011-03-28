require 'twos_complement'
require 'ssh_public_key/blob_reader'
require 'ssh_public_key/blob_writer'

module SSHPublicKey

  module_function

  def parse(text)
    plaintext_sigil, blob, comment = text.split(/\s/)
    bytes = blob.unpack("m").first
    case text
    when /^ssh-rsa/
      sigil, e, m = BlobReader.new(bytes).read_string.
                                          read_bigint.
                                          read_bigint.values
      RSAPublicKey.new(:e => e, :m => m, :comment => comment)
    when /^ssh-dss/
      sigil, p, q, g, y = BlobReader.new(bytes).read_string.
                                                read_bigint.
                                                read_bigint.
                                                read_bigint.
                                                read_bigint.values
      DSAPublicKey.new(:p => p, :q => q, :g => g, :y => y, :comment => comment)
    end
  end

  class RSAPublicKey
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
      bytes = BlobWriter.new.write_string(sigil).write_bigint(e).write_bigint(m).to_s
      [bytes].pack("m").tr("\n", "")
    end

    def to_s
      [sigil, blob, comment].join(" ")
    end
  end

  class DSAPublicKey
    attr_reader :p, :q, :g, :y, :comment

    def initialize(params)
      @p       = params[:p]
      @q       = params[:q]
      @g       = params[:g]
      @y       = params[:y]
      @comment = params[:comment]
    end

    def algorithm
      'DSA'
    end

    def sigil
      'ssh-dss'
    end

    def blob
      bytes = BlobWriter.new.write_string(sigil).
                             write_bigint(p).
                             write_bigint(q).
                             write_bigint(g).
                             write_bigint(y).to_s
      [bytes].pack("m").tr("\n", "")
    end

    def to_s
      [sigil, blob, comment].join(" ")
    end
  end
end
