"""Contains tests for KpwnWriter."""

import io
import unittest
from converter.binary_writer import BinaryWriter
from converter.image_db_target import ImageDbTarget
from converter.kpwn_writer import KpwnWriter
from converter.kpwn_writer import SymbolWriter
from data_model.db import Db
from data_model.meta import MetaConfig
from test.utils import RELEASES_DIR

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
    config = MetaConfig.from_desc({0x11223344: "SYMBOL_1", 0x55667788: "SYMBOL_2"})
    sw = SymbolWriter(config.symbols)

    bw = BinaryWriter()
    sw.write_meta(bw)

    expect(b"\x02\0\0\0" +              # symbols len
           b"\x0f\0" +                  # symbols[0].sizeof
           b"\x44\x33\x22\x11" +        # symbols[0].type_id == 0x11223344
           b"\x08\0" + b"SYMBOL_1\0" +  # symbols[0].name == "SYMBOL_1"
           b"\x0f\0" +                  # symbols[1].sizeof
           b"\x88\x77\x66\x55" +        # symbols[1].type_id == 0x55667788
           b"\x08\0" + b"SYMBOL_2\0",   # symbols[1].name == "SYMBOL_2"
           bw.data())

  def test_target(self):
    config = MetaConfig.from_desc({1: "msleep", 2: "anon_pipe_buf_ops"})
    sw = SymbolWriter(config.symbols)
    target = ImageDbTarget("", "", f"{RELEASES_DIR}/kernelctf/lts-6.1.36").process()

    bw = BinaryWriter()
    sw.write_target(bw, target)

    expect(b"\xe0\x92\x22\x00" +  # msleep
           b"\x80\xcf\xa1\x01",   # anon_pipe_buf_ops
           bw.data())


class KpwnWriterTests(unittest.TestCase):
  """Tests for the KpwnWriter class."""

  EXPECTED_HDR = b"KPWN" + b"\x01\x00" + b"\x01\x00"  # v1.1

  def expect(self, expected, symbols_desc={}, actions_desc={}, targets=[]):
    meta = MetaConfig.from_desc(symbols_desc, actions_desc)
    db = Db(meta, targets)
    stream = io.BytesIO()
    KpwnWriter(db).write(stream)
    expect(expected, stream.getvalue())

  def test_empty(self):
    self.expect(self.EXPECTED_HDR +
                b"\x0d\0\0\0" +  # meta len
                b"\x00\0\0\0" +  # num_symbols
                b"\x00\0\0\0" +  # num_rop_actions
                b"\x00" +        # structs.size
                b"\x1d\0\0\0" +  # struct_layouts_db_offset
                b"\x00\0\0\0" +  # num_targets
                b"\x00")         # struct_layouts.size

  def test_msleep(self):
    self.expect(self.EXPECTED_HDR +
                b"\x1c\0\0\0" +              # meta len
                b"\x01\0\0\0" +              # num_symbols
                b"\x0d\0" +                  # symbols[0].sizeof
                b"\x44\x33\x22\x11" +        # symbols[0].type_id == 0x11223344
                b"\x06\x00" + b"msleep\0" +  # symbols[0].name == "msleep"
                b"\x00\0\0\0" +              # num_rop_actions
                b"\x00" +                    # structs.size
                b"\x2c\0\0\0" +              # struct_layouts_db_offset
                b"\x00\0\0\0" +              # num_targets
                b"\x00",                     # struct_layouts.size
                {0x11223344: "msleep"})

  def test_target(self):
    target = ImageDbTarget("kernelCTF", "lts-6.1.36",
                           f"{RELEASES_DIR}/kernelctf/lts-6.1.36").process()

    self.expect(self.EXPECTED_HDR +
                b"\x0d\0\0\0" +                # meta len
                b"\x00\0\0\0" +                # num_symbols
                b"\x00\0\0\0" +                # num_rop_actions
                b"\x00" +                      # structs.size
                b"\x61\0\0\0" +                # struct_layouts_db_offset
                b"\x01\0\0\0" +                # num_targets
                b"\x40\0\0\0" +                # t[0].sizeof
                b"\x09\0" + b"kernelCTF\0" +   # t[0].distro
                b"\x0a\0" + b"lts-6.1.36\0" +  # t[0].release_name
                # t[0].version
                b"\x1e\0" + b"KernelCTF version 6.1.36 (...)\x00" +
                b"\x04\x00" +                  # t[0].pivots.struct_size
                b"\0" +                        # t[0].pivots.one_gadgets.len
                b"\0" +                        # t[0].pivots.push_indirects.len
                b"\0" +                        # t[0].pivots.pop_rsps.len
                b"\0" +                        # t[0].pivots.stack_shifts.len
                b"\x00" +                      # struct_layouts.size
                b"",
                targets=[target])
