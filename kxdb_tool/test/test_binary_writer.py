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

"""Contains tests for BinaryWriter."""

import contextlib
import unittest
from converter.binary_writer import BinaryWriter

class BinaryWriterTests(unittest.TestCase):
  """Tests for the BinaryWriter class."""

  @contextlib.contextmanager
  def expect(self, expected):
    bw = BinaryWriter()
    yield bw
    self.assertEqual(expected, bw.data())

  def test_u1(self):
    with self.expect(b"\x11") as bw:
      bw.u1(0x11)

  def test_u2(self):
    with self.expect(b"\x22\x11") as bw:
      bw.u2(0x1122)

  def test_u4(self):
    with self.expect(b"\x44\x33\x22\x11") as bw:
      bw.u4(0x11223344)

  def test_u8(self):
    with self.expect(b"\x88\x77\x66\x55\x44\x33\x22\x11") as bw:
      bw.u8(0x1122334455667788)

  def test_zstr_raw(self):
    with self.expect(b"content\x00") as bw:
      bw.zstr_raw("content")

  def test_zstr(self):
    with self.expect(b"\x07content\x00") as bw:
      bw.zstr("content")

  def test_zstr_u2(self):
    with self.expect(b"\x07\x00content\x00") as bw:
      bw.zstr_u2("content")

  def varint_test(self, expected, value, signed):
    with self.expect(expected) as bw:
      bw.varint(value, signed)

  def test_varuint(self):
    tests = {
            0      : b"\x00",
            1      : b"\x01",
          127      : b"\x7f",
          128      : b"\x80\x01",
          129      : b"\x81\x01",
          255      : b"\xff\x01",
          256      : b"\x80\x02",
      127*128      : b"\x80\x7f",
      127*128 +   1: b"\x81\x7f",
      127*128 + 127: b"\xff\x7f",
      127*128 + 128: b"\x80\x80\x01",
    }

    for (value, expected) in tests.items():
      self.varint_test(expected, value, False)

  def test_varsint(self):
    tests = {
        0: b"\x00",
        1: b"\x01",
       63: b"\x3f",
       -1: b"\x40",
       -2: b"\x41",
      -64: b"\x7f",
       64: b"\x80\x01",
       65: b"\x81\x01",
      -65: b"\xc0\x01",
      -66: b"\xc1\x01",
    }

    for (value, expected) in tests.items():
      self.varint_test(expected, value, True)

  def test_struct(self):
    with self.expect(b"\x06" + b"\x05" + b"ABCD\x00") as bw:
      with bw.struct() as inner:
        with inner.struct() as nested:
          nested.zstr_raw("ABCD")
