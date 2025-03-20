"""Classes for writing the kpwn file format."""
from data_model.db import Db, Target
from data_model.meta import MetaConfig
from converter.binary_reader import BinaryReader
from converter.symbols import SymbolReader
from converter.rop_actions import RopActionReader
from converter.stack_pivots import StackPivotReader
from converter.structs import StructReader

MAGIC = "KPWN"
VERSION_MAJOR = 1
VERSION_MINOR = 1

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
    if major_ver > VERSION_MAJOR:
      raise KpwnReaderException(f"reading {major_ver} is not supported (only {VERSION_MAJOR} or earlier)")

    structs_supported = minor_ver >= 1

    # meta header
    r_meta = r_root.struct(4)
    symbols_meta = self.symbol_reader.read_meta(r_meta)
    rop_actions_meta = self.rop_action_reader.read_meta(r_meta)
    structs_meta = self.struct_reader.read_meta(r_meta) if structs_supported else []
    meta = MetaConfig(symbols_meta, rop_actions_meta, structs_meta)

    if structs_supported:
      self.struct_reader.read_struct_layouts(r_root)

    # targets
    targets = []
    for _ in range(r_root.u4()):
      r_target = r_root.struct(4)
      distro = r_target.zstr_u2()
      release_name = r_target.zstr_u2()
      version = r_target.zstr_u2()

      symbols = self.symbol_reader.read_target(r_target)
      rop_actions = self.rop_action_reader.read_target(r_target)
      stack_pivots = self.stack_pivot_reader.read_target(r_target)
      structs = self.struct_reader.read_target(r_target) if structs_supported else {}

      target = Target(distro, release_name, version,
                      symbols, rop_actions, stack_pivots, structs)

      targets.append(target)

    return Db(meta, targets)

  def read_from_file(self, fn):
    with open(fn, "rb") as f:
      return self.read(f)
