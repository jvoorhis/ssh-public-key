require 'base64'

module SSHPublicKey
  module_function

  def parse(text)
    plaintext_sigil, blob, comment = text.split(/\s/)
    bytes = Base64.decode64(blob)
    case text
    when /^ssh-rsa/
      sigil, e, m = BlobParser.parse(bytes, :string, :bigint, :bigint)
      RSAPublicKey.new(:parameters => { 'e' => e, 'm' => m }, :comment => comment)
    when /^ssh-dss/
      sigil, p, q, g, y = BlobParser.parse(bytes, :string, :bigint, :bigint, :bigint, :bigint)
      DSAPublicKey.new(:parameters => { 'p' => p, 'q' => q, 'g' => g, 'y' => y }, :comment => comment)
    end
  end

  class BlobParser < Struct.new(:bytes, :pos, :value)
    def self.parse(bytes, *fields)
      values = []
      initial_parser = BlobParser[bytes, 0, nil]
      values, final_parser = fields.inject([values, initial_parser]) do |(values, parser), field|
        parser.send(:"read_#{field}") do |parser|
          [values + Array(parser.value), parser]
        end
      end
      values
    end

    def read(type)
      send(:"read_#{type}") { |parser| yield parser }
    end

    def read_string
      read_int do |int|
        size  = int.value
        value = bytes[int.pos, size].unpack("a*").first
        yield BlobParser[bytes, int.pos+size, value]
      end
    end

    def read_int
      size  = 4
      value = bytes[pos, size].unpack("N").first
      yield BlobParser[bytes, pos + size, value]
    end

    def read_bigint
      read_int do |int|
        size  = int.value
        value = bytes[int.pos, size].unpack("c" + "C" * (size-1)).inject(0) { |i,b| (i << 8) | b }
        yield BlobParser[bytes, int.pos + size, value]
      end
    end
  end

  class PublicKey
    private_class_method :new

    attr_reader :parameters, :comment

    def initialize(options = {})
      @parameters = options[:parameters]
      @comment    = options[:comment]
    end
  end

  class RSAPublicKey < PublicKey
    public_class_method :new

    def algorithm
      'RSA'
    end
  end

  class DSAPublicKey < PublicKey
    public_class_method :new

    def algorithm
      'DSA'
    end
  end
end
