"""Module containing classes related to writing binary data."""
import contextlib
import struct


class BinaryWriter:
  """Utility class to write binary data into a file or bytearray more easily."""

  def __init__(self, data=None):
    self.data = data if data is not None else bytearray()
    self.data_is_bytearray = isinstance(self.data, bytearray)

  def write(self, bytes_):
    if self.data_is_bytearray:
      self.data.extend(bytes_)
    else:
      self.data.write(bytes_)

  def zstr(self, str_):
    self.write(bytes(str_, "ascii"))
    self.write(b"\x00")

  def zstr_u2(self, str_):
    """Writes a zero-terminated string prefixed with its length as a uint16 field."""
    self.u2(len(str_))
    self.zstr(str_)

  def uint(self, size, value):
    format_ = {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
    self.write(struct.pack("<" + format_, value))

  def u1(self, value):
    self.uint(1, value)

  def u2(self, value):
    self.uint(2, value)

  def u4(self, value):
    self.uint(4, value)

  def u8(self, value):
    self.uint(8, value)

  @contextlib.contextmanager
  def struct(self, struct_size_len=2):
    sub_writer = BinaryWriter()
    try:
      yield sub_writer
    finally:
      self.uint(struct_size_len, len(sub_writer.data))    # struct_size
      self.write(sub_writer.data)
