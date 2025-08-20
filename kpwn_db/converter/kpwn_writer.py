"""Classes for writing the kpwn file format."""
import os

from converter.binary_writer import BinaryWriter, SectionDict
from converter.symbols import SymbolWriter
from converter.rop_actions import RopActionWriter
from converter.stack_pivots import StackPivotWriter
from converter.structs import StructWriter
from converter.consts import MAGIC, VERSION_MAJOR, VERSION_MINOR, SECTION_META, SECTION_TARGETS, SECTION_STRUCT_LAYOUTS

class KpwnWriter:
  """Class to write the kpwn file format."""

  def __init__(self, db):
    self.symbol_writer = SymbolWriter(db.meta.symbols)
    self.rop_action_writer = RopActionWriter(db.meta.rop_actions)
    self.stack_pivot_writer = StackPivotWriter()
    self.struct_writer = StructWriter(db.meta.structs)
    self.db = db

  def write(self, f):
    wr_root = BinaryWriter(f)
    wr_root.write(bytes(MAGIC, "ascii"))
    wr_root.u2(VERSION_MAJOR)
    wr_root.u2(VERSION_MINOR)

    sections = SectionDict(wr_root, 3)

    # meta header
    with sections.add(SECTION_META) as wr_hdr:
      self.symbol_writer.write_meta(wr_hdr)
      self.rop_action_writer.write_meta(wr_hdr)
      self.struct_writer.write_meta(wr_hdr)

    # targets
    with sections.add(SECTION_TARGETS) as wr_targets:
      for (wr_target, target) in wr_targets.seekable_list(self.db.targets):
        wr_target.zstr(target.distro)
        wr_target.zstr(target.release_name)
        wr_target.zstr(target.version)

        self.symbol_writer.write_target(wr_target, target)
        self.rop_action_writer.write_target(wr_target, target)
        self.stack_pivot_writer.write_target(wr_target, target)
        self.struct_writer.write_target(wr_target, target)

    # struct layouts
    with sections.add(SECTION_STRUCT_LAYOUTS) as wr:
        self.struct_writer.write_struct_layouts(wr)

  def write_to_file(self, fn):
    os.makedirs(os.path.abspath(os.path.dirname(fn)), exist_ok=True)
    with open(fn, "wb") as f:
      self.write(f)
