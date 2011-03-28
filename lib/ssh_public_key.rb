class Integer
  def self.from_twos_complement(bytestring)
    bytestring.unpack("cC*").inject(0) { |i,b| (i << 8) | b }
  end

  def to_twos_complement
    int = self
    bytearray = []
    begin
      bytearray << (int & 0xff)
      int >>= 8
    end until (int == 0 || int == -1) && (bytearray.last[7] == int[7])
    bytearray.reverse!
    bytearray.pack("c" + "C*")
  end
end

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

  class BlobReader
    attr_reader :bytes, :pos, :values

    def initialize(bytes, pos = 0, values = [])
      @bytes  = bytes
      @pos    = pos
      @values = values
    end

    def read_string
      int = read_int
      size = int.values.last
      value = bytes[int.pos, size].unpack("a*").first
      BlobReader.new(bytes, int.pos + size, values + [value])
    end

    def read_int
      size  = 4
      value = bytes[pos, size].unpack("N").first
      BlobReader.new(bytes, pos + size, values + [value])
    end

    def read_bigint
      int   = read_int
      size  = int.values.last
      value = Integer.from_twos_complement(bytes[int.pos, size])
      BlobReader.new(bytes, int.pos + size, values + [value])
    end
  end

  class BlobWriter
    attr_reader :bytes

    def initialize(bytes = "")
      @bytes = bytes
    end

    alias :to_s :bytes

    def write_int(int)
      BlobWriter.new(bytes + [int].pack("N"))
    end

    def write_string(string)
      bytestring = [string].pack("a*")
      BlobWriter.new(
        write_int(bytestring.bytesize).bytes + bytestring)
    end

    def write_bigint(bigint)
      bytestring = bigint.to_twos_complement
      BlobWriter.new(
        write_int(bytestring.bytesize).bytes + bytestring)
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
