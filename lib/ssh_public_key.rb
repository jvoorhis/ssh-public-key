require 'base64'

module SSHPublicKey
  module_function

  def parse(text)
    case text
    when /^ssh-rsa/ then RSAPublicKey.new(text)
    when /^ssh-dss/ then DSAPublicKey.new(text)
    end
  end

  class PublicKey
    attr_reader :parameters

    protected

    def decode_type
      size = decode_int
      @bytes[@pos, size].unpack("a*").first.tap do
        @pos += size
      end
    end

    def decode_int
      size = 4
      @bytes[@pos, size].unpack("N").first.tap do
        @pos += size
      end
    end

    def decode_bigint
      size = decode_int
      @bytes[@pos, size].unpack("c" + "C" * (size-1)).inject(0) { |i,b| (i << 8) | b }.tap do
        @pos += size
      end
    end
  end

  class RSAPublicKey < PublicKey
    def initialize(text)
      @text = text
      blob = text.split(/\s/).detect { |part| part =~ /^AAAA/ }
      @bytes = Base64.decode64(blob)
      @pos = 0
      type_sigil = decode_type
      type_sigil = 'ssh-rsa' or fail
      @parameters = decode_parameters
    end

    def algorithm
      'RSA'
    end

    protected

    def decode_parameters
      e = decode_bigint
      m = decode_bigint
      { 'e' => e, 'm' => m }
    end
  end

  class DSAPublicKey < PublicKey
    def initialize(text)
      @text = text
      blob = text.split(/\s/).detect { |part| part =~ /^AAAA/ }
      @bytes = Base64.decode64(blob)
      @pos = 0
      type_sigil = decode_type
      type_sigil == 'ssh-dss' or fail
      @parameters = decode_parameters
    end
    
    def algorithm
      'DSA'
    end

    protected

    def decode_parameters
      p = decode_bigint
      q = decode_bigint
      g = decode_bigint
      y = decode_bigint
      { 'p' => p, 'q' => q, 'g' => g, 'y' => y }
    end
  end
end
