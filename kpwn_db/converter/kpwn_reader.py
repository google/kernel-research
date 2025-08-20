"""Classes for writing the kpwn file format."""
from data_model.db import Db, Target
from data_model.meta import MetaConfig
from converter.binary_reader import BinaryReader
from converter.symbols import SymbolReader
from converter.rop_actions import RopActionReader
from converter.stack_pivots import StackPivotReader
from converter.structs import StructReader
from converter.consts import MAGIC, VERSION_MAJOR, VERSION_MINOR, SECTION_STRUCT_LAYOUTS

class KpwnReaderException(Exception):
  pass

class KpwnReader:
  """Class to read the kpwn file format."""

  def __init__(self):
    self.symbol_reader = SymbolReader()
    self.rop_action_reader = RopActionReader()
    self.stack_pivot_reader = StackPivotReader()
    self.struct_reader = StructReader()

  def read(self, f):
    r_root = BinaryReader(f.read())

    magic = r_root.read(len(MAGIC))
    if magic.decode('ascii') != MAGIC:
      raise KpwnReaderException(f"expected magic '{MAGIC}', but got {magic}")

    major_ver = r_root.u2()
    minor_ver = r_root.u2()
    if major_ver != VERSION_MAJOR:
      raise KpwnReaderException(f"reading {major_ver} is not supported (only {VERSION_MAJOR})")

    # skip section_offsets
    sections = r_root.sections_dict()

    # meta header
    symbols_meta = self.symbol_reader.read_meta(r_root)
    rop_actions_meta = self.rop_action_reader.read_meta(r_root)
    structs_meta = self.struct_reader.read_meta(r_root)
    meta = MetaConfig(symbols_meta, rop_actions_meta, structs_meta)
    self.struct_reader.read_struct_layouts(r_root, sections[SECTION_STRUCT_LAYOUTS]["offset"])

    # targets
    targets = []
    for _ in range(len(r_root.seekable_list())):
      distro = r_root.zstr()
      release_name = r_root.zstr()
      version = r_root.zstr()

      symbols = self.symbol_reader.read_target(r_root)
      rop_actions = self.rop_action_reader.read_target(r_root)
      stack_pivots = self.stack_pivot_reader.read_target(r_root)
      structs = self.struct_reader.read_target(r_root)

      target = Target(distro, release_name, version,
                      symbols, rop_actions, stack_pivots, structs)

      targets.append(target)

    return Db(meta, targets)

  def read_from_file(self, fn):
    with open(fn, "rb") as f:
      return self.read(f)
