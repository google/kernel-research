"""Classes for writing the kpwn file format."""
import os

from converter.binary_writer import BinaryWriter
from converter.symbols import SymbolWriter
from converter.rop_actions import RopActionWriter
from converter.stack_pivots import StackPivotWriter

MAGIC = "KPWN"
VERSION_MAJOR = 1
VERSION_MINOR = 0


class KpwnWriter:
  """Class to write the kpwn file format."""

  def __init__(self, db):
    self.symbol_writer = SymbolWriter(db.meta.symbols)
    self.rop_action_writer = RopActionWriter(db.meta.rop_actions)
    self.stack_pivot_writer = StackPivotWriter()
    self.db = db

  def write(self, f, minimal=False):
    wr_root = BinaryWriter(f)
    wr_root.write(bytes(MAGIC, "ascii"))
    wr_root.u2(VERSION_MAJOR)
    wr_root.u2(VERSION_MINOR)

    # meta header
    with wr_root.struct(4) as wr_hdr:
      # symbols
      self.symbol_writer.write_meta(wr_hdr, minimal)

      # ROP Actions
      self.rop_action_writer.write_meta(wr_hdr, minimal)

    # targets
    wr_root.u4(len(self.db.targets))
    for target in self.db.targets:
      with wr_root.struct(4) as wr_target:
        wr_target.zstr_u2(target.distro)
        wr_target.zstr_u2(target.release_name)
        wr_target.zstr_u2(target.version)

        # symbols
        self.symbol_writer.write_target(wr_target, target)

        # ROP Actions
        self.rop_action_writer.write_target(wr_target, target)

        # Stack Pivots
        self.stack_pivot_writer.write_target(wr_target, target)

  def write_to_file(self, fn, minimal=False):
    os.makedirs(os.path.abspath(os.path.dirname(fn)), exist_ok=True)
    with open(fn, "wb") as f:
      self.write(f, minimal)
