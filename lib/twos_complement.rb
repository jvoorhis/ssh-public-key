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
