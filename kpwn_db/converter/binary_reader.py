"""Module containing classes related to reading binary data."""
import struct


class BinaryReader:
  """Utility class to read binary data from a file or a bytearray more easily."""

  def __init__(self, data=None):
    self.data = data
    self.offset = 0

  def read(self, len_):
    result = self.data[self.offset : self.offset + len_]
    self.offset += len_
    return result

  def zstr_u2(self):
    """Reads a zero-terminated string prefixed with its length as a uint16 field."""
    len_ = self.u2()
    result = self.read(len_)
    self.offset += 1
    return result

  def uint(self, size):
    format_ = {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
    return struct.unpack("<" + format_, self.read(size))[0]

  def u1(self):
    return self.uint(1)

  def u2(self):
    return self.uint(2)

  def u4(self):
    return self.uint(4)

  def u8(self):
    return self.uint(8)

  def varint(self, signed):
    byte = self.u1()
    negative = signed and (byte & 0x40)
    result = byte & (0x3f if signed else 0x7f)
    shift = 6 if signed else 7
    while byte & 0x80:
      byte = self.u1()
      result |= (byte & 0x7f) << shift
      shift += 7
    return ~result if negative else result

  def varuint(self):
    return self.varint(False)

  def varsint(self):
    return self.varint(True)

  def struct(self, struct_size_len=2):
    data_len = self.uint(struct_size_len)    # struct_size
    return BinaryReader(self.read(data_len)) if data_len > 0 else None
