# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
  def struct(self, struct_size_len=2):
    size_field = self.reserve(struct_size_len)
    start_offset = self.size()
    yield self
    size_field.uint(struct_size_len, self.size() - start_offset) # struct_size

  def list(self, list_):
    self.varuint(len(list_))
    for item in list_:
      yield item

  def seekable_list(self, list_):
    #self.varuint(len(list_))
    bw = BinaryWriter()
    end_offsets = []
    for item in list_:
      yield (bw, item)
      end_offsets.append(bw.size())

    max_offs = end_offsets[-1] if end_offsets else 0
    offset_size = 1 if max_offs < 256 else 2 if max_offs < 65536 else 4

    self.varuint((offset_size - 1) | len(end_offsets) << 2)
    for offs in end_offsets:
      self.uint(offset_size, offs)
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

