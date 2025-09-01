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

"""Module containing classes related to reading binary data."""
import struct
import contextlib

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

  def zstr(self):
    """Reads a zero-terminated string prefixed with its length as a varuint field."""
    len_ = self.varuint()
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

  def varuint_extra(self, extra_bit_len):
    raw_value = self.varuint()
    extra_bits = raw_value & ((1 << extra_bit_len) - 1)
    value = raw_value >> extra_bit_len
    return (extra_bits, value)

  def varsint(self):
    return self.varint(True)

  def struct(self):
    data_len = self.varuint()    # struct_size
    return BinaryReader(self.read(data_len)) if data_len > 0 else None

  def list(self):
    return range(self.varuint())

  @contextlib.contextmanager
  def seek(self, offs):
    saved_offset = self.offset
    self.offset = offs
    yield
    self.offset = saved_offset

  def indexable_int_list(self):
    hdr = self.varuint()
    item_size = 1 << (hdr & 0x3)  # 0=u1, 1=u2, 2=u4, 3=u8
    item_count = hdr >> 2
    items = []
    for _ in range(item_count):
      items.append(self.uint(item_size))
    return items

  def seekable_list(self):
    hdr = self.varuint()
    offset_size = 1 << (hdr & 0x3)  # 0=u1, 1=u2, 2=u4, 3=u8
    item_count = hdr >> 2
    self.offset += item_count * offset_size
    return range(item_count)

  def seekable_list_sizes(self):
    end_offsets = self.indexable_int_list()
    sizes = []
    start_offset = 0
    for end_offset in end_offsets:
      sizes.append(end_offset - start_offset)
      start_offset = end_offset
    return sizes

  def sections_dict(self):
    sections = {}
    num_sections = self.u2()
    for _ in range(num_sections):
      id = self.u2()
      offset = self.u4()
      size = self.u4()
      sections[id] = {"offset": offset, "size": size}
    return sections


