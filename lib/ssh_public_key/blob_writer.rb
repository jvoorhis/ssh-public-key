module SSHPublicKey
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
end
