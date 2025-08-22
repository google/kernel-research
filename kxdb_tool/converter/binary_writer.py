"""Module containing classes related to writing binary data."""
import contextlib
import io
import struct

class BinaryWriter:
  """Utility class to write binary data into a file or bytearray more easily."""

  def __init__(self, file=None):
    self.file = file if file is not None else io.BytesIO()

  def write(self, bytes_):
    self.file.write(bytes_)

  def zstr_raw(self, str_):
    self.write(bytes(str_, "ascii"))
    self.write(b"\x00")

  def zstr(self, str_):
    self.varuint(len(str_))
    self.zstr_raw(str_)

  def zstr_u2(self, str_):
    """Writes a zero-terminated string prefixed with its length as a uint16 field."""
    self.u2(len(str_))
    self.zstr_raw(str_)

  def uint(self, size, value):
    if size == 0:
      return self.varuint(value)

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

  def varint(self, value, signed):
    if value == 0:
      self.u1(0)
      return

    negative = value < 0
    if negative and not signed:
      raise ValueError(f"trying to write value '{value}' as unsigned number")
    value = ~value if negative else value

    if signed:
      self.u1((0x80 if value > 63 else 0) |
              (0x40 if negative else 0) |
              (value & 63))
      value >>= 6

    while value:
      self.u1((0x80 if value > 127 else 0) | (value & 127))
      value >>= 7

  def varuint(self, value):
    self.varint(value, False)

  def varsint(self, value):
    self.varint(value, True)

  def varuint_extra(self, extra_bit_len, extra_val, data_val):
    self.varuint(extra_val | (data_val << extra_bit_len))

  def size(self):
    return self.file.tell()

  def data(self):
    return self.file.getvalue()

  def overwrite(self, offset, new_value):
    current_offset = self.size()
    self.file.seek(offset, io.SEEK_SET)
    self.file.write(new_value)
    self.file.seek(current_offset, io.SEEK_SET)

  @contextlib.contextmanager
  def struct(self):
    bw = BinaryWriter()
    yield bw
    self.varuint(bw.size())
    self.write(bw.data())

  def list(self, list_):
    self.varuint(len(list_))
    for item in list_:
      yield item

  def indexable_int_list(self, list_):
    max_offs = max(list_) if list_ else 0
    offset_size = 0 if max_offs < 2**8 else 1 if max_offs < 2**16 else 2 if max_offs < 2**24 else 3

    self.varuint(offset_size | len(list_) << 2)
    for item in list_:
      self.uint(1 << offset_size, item)

  def seekable_list(self, list_):
    #self.varuint(len(list_))
    bw = BinaryWriter()
    end_offsets = []
    for item in list_:
      yield (bw, item)
      end_offsets.append(bw.size())

    self.indexable_int_list(end_offsets)
    self.write(bw.data())

  # Reserve fields to be written later. Usage example:
  #   reserved_field = writer.reserve(4)
  #   ... write another things ...
  #   reserved_field.u4(0xAABBCCDD)
  def reserve(self, size):
    reserved_offset = self.size()
    self.file.write(bytes(size))
    return ReservedRange(self, reserved_offset, size)

class ReservedRange(BinaryWriter):
  def __init__(self, parent_writer, offset, size):
    super().__init__()
    self.parent_writer = parent_writer
    self.offset = 0
    self.reserved_offset = offset
    self.reserved_size = size

  def write(self, bytes_):
    if self.offset + len(bytes_) > self.reserved_size:
      raise RuntimeError(f"Field was reserved for {self.reserved_size} bytes"
        f"but tried to write {len(bytes_)} bytes at offset {self.offset}")

    self.parent_writer.overwrite(self.reserved_offset + self.offset, bytes_)
    self.offset += len(bytes_)

class SectionDict:
  def __init__(self, wr, capacity):
    self.wr = wr
    self.capacity = capacity
    self.used = 0

    wr.u2(capacity)
    # 10 = type_id (u2) + start_offset (u4) + end_offset (u4)
    self.wr_dict = wr.reserve(capacity * 10)

  @contextlib.contextmanager
  def add(self, type_id):
    if self.used >= self.capacity:
      raise Exception(f"Section dictionary is full, capacity: {self.capacity}")
    self.used += 1

    start_offset = self.wr.size()
    self.wr_dict.u2(type_id)
    self.wr_dict.u4(start_offset)
    yield self.wr
    self.wr_dict.u4(self.wr.size() - start_offset) # size

