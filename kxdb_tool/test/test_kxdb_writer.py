"""Contains tests for KxdbWriter."""

import io
import unittest
from converter.binary_writer import BinaryWriter
from converter.image_db_target import ImageDbTarget
from converter.kxdb_writer import KxdbWriter
from converter.kxdb_writer import SymbolWriter
from data_model.db import Db
from data_model.meta import MetaConfig
from test.utils import RELEASES_DIR
import struct

def expect(expected, actual):
  for i in range(min(len(expected), len(actual))):
    if expected[i] != actual[i]:
      raise AssertionError(f"diffence at offset {i}: "
                           f"{expected[i:].hex()} != {actual[i:].hex()}")

  if len(expected) != len(actual):
    raise AssertionError(f"expected data with len {len(expected)} "
                         f"but got {len(actual)}")


class SymbolWriterTests(unittest.TestCase):
  """Tests for the SymbolWriter class."""

  def test_meta(self):
    config = MetaConfig.from_desc(["SYMBOL_1", "SYMBOL_2"])
    sw = SymbolWriter(config.symbols)

    bw = BinaryWriter()
    sw.write_meta(bw)

    expect(bytes([2 << 2, 10, 20]) +  # symbols seek list, count=2, end_offsets=10,20
           b"\x08" + b"SYMBOL_1\0" +  # symbols[0].name == "SYMBOL_1"
           b"\x08" + b"SYMBOL_2\0",   # symbols[1].name == "SYMBOL_2"
           bw.data())

  def test_target(self):
    config = MetaConfig.from_desc(["msleep", "anon_pipe_buf_ops"])
    sw = SymbolWriter(config.symbols)
    target = ImageDbTarget("", "", f"{RELEASES_DIR}/kernelctf/lts-6.1.36").process()

    bw = BinaryWriter()
    sw.write_target(bw, target)

    # symbols are stored in alphabetical order to allow binsearch
    expect(struct.pack("<I", 0x1a1cf80) + # anon_pipe_buf_ops
           struct.pack("<I", 0x2292e0),   # msleep
           bw.data())


class KxdbWriterTests(unittest.TestCase):
  """Tests for the KxdbWriter class."""

  EXPECTED_HDR = b"KXDB" + b"\x01\x00" + b"\x01\x00"  # v1.1

  def expect(self, expected, symbols_desc=[], actions_desc={}, targets=[]):
    meta = MetaConfig.from_desc(symbols_desc, actions_desc)
    db = Db(meta, targets)
    stream = io.BytesIO()
    KxdbWriter(db).write(stream)
    expect(expected, stream.getvalue())

  def expect_smart(self, meta, targets, layouts, symbols_desc=[], actions_desc={}, targets_desc=[]):
    meta_start = 0x28
    meta_size = len(meta)
    targets_start = meta_start + meta_size
    targets_size = len(targets)
    layouts_start = targets_start + targets_size
    layouts_size = len(layouts)

    self.expect(self.EXPECTED_HDR +
                b"\x03\0" +      # num_section_offsets
                b"\x01\0" +      # section_offsets[META].type_id
                struct.pack("<I", meta_start) +
                struct.pack("<I", meta_size) +
                b"\x02\0" +      # section_offsets[TARGETS].type_id
                struct.pack("<I", targets_start) +
                struct.pack("<I", targets_size) +
                b"\x03\0" +      # section_offsets[STRUCT_LAYOUTS].type_id
                struct.pack("<I", layouts_start) +
                struct.pack("<I", layouts_size) +
                meta + targets + layouts,
                symbols_desc, actions_desc, targets_desc)

  def test_empty(self):
    self.expect_smart(
                b"\x00" +        # meta.symbols.count
                b"\x00" +        # meta.rop_actions.count
                b"\x00",         # meta.structs.count
                b"\x00" +        # targets_by_version.count
                b"\x00",         # targets.count
                b"\x00")         # struct_layouts.count

  def test_msleep(self):
    self.expect_smart(
                bytes([1 << 2, 8]) +     # meta.symbols seekable: item_count = 1, len(symbols[0]) = 8
                b"\x06" + b"msleep\0" +  # meta.symbols[0].name == "msleep"
                b"\x00" +                # meta.rop_actions.count
                b"\x00",                 # meta.structs.count
                b"\x00" +                # targets_by_version.count
                b"\x00",                 # targets.count
                b"\x00",                 # struct_layouts.count
                ["msleep"])

  def test_target(self):
    target = ImageDbTarget("kernelCTF", "lts-6.1.36",
                           f"{RELEASES_DIR}/kernelctf/lts-6.1.36").process()

    t0 = (b"\x09" + b"kernelCTF\0" +   # t[0].distro
          b"\x0a" + b"lts-6.1.36\0" +  # t[0].release_name
          # t[0].version
          b"\x1e" + b"KernelCTF version 6.1.36 (...)\x00" +
          b"\0" +                      # t[0].rop_actions.len = 0
          b"\x04" +                    # t[0].pivots.struct_size
          b"\0" +                      # t[0].pivots.one_gadgets.count
          b"\0" +                      # t[0].pivots.push_indirects.count
          b"\0" +                      # t[0].pivots.pop_rsps.count
          b"\0")                       # t[0].pivots.stack_shifts.count


    self.expect_smart(
                b"\x00" +        # meta.symbols.count
                b"\x00" +        # meta.rop_actions.count
                b"\x00",         # meta.structs.count

                # item_count = 1, offset_size = u1 (0), 1 << 2 | 0 = 4
                bytes([1 << 2, 0]) +          # targets_by_version[0] = 0
                bytes([1 << 2, len(t0)]) +    # end_offset[0] = len(t0)
                t0,
                b"\x00",                      # struct_layouts.count
                targets_desc=[target])
