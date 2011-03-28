module SSHPublicKey
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
end
