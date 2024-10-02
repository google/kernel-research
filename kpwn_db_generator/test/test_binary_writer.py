"""Contains tests for BinaryWriter."""

import contextlib
import unittest
from binary_writer import BinaryWriter


class BinaryWriterTests(unittest.TestCase):
  """Tests for the BinaryWriter class."""

  @contextlib.contextmanager
  def expect(self, expected):
    bw = BinaryWriter()
    yield bw
    self.assertEqual(expected, bw.data)

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

  def test_zstr(self):
    with self.expect(b"content\x00") as bw:
      bw.zstr("content")

  def test_zstr_u2(self):
    with self.expect(b"\x07\x00content\x00") as bw:
      bw.zstr_u2("content")

  def test_struct(self):
    with self.expect(b"\x07\x00\x00\x00" + b"\x05\x00" + b"ABCD\x00") as bw:
      with bw.struct(4) as inner:
        with inner.struct() as nested:
          nested.zstr("ABCD")
