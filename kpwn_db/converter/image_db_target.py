"""Processes per-target files from kernel-image-db folders."""
import os
from data_model.db import Target
from data_model.pivots import PivotSerializer
from data_model.rop_chain import RopActionSerializer

class ImageDbTarget:
  """Processes per-target files from kernel-image-db folders."""

  KBASE_ADDR = 0xffffffff81000000
  VERSION_TXT = "version.txt"
  SYMBOLS_TXT = "symbols.txt"
  ROP_ACTIONS_JSON = "rop_actions.json"
  STACK_PIVOTS_JSON = "stack_pivots.json"
  ALL_FILES = [VERSION_TXT, SYMBOLS_TXT, ROP_ACTIONS_JSON, STACK_PIVOTS_JSON]

  def __init__(self, distro, release_name, dir_):
    self.distro = distro
    self.release_name = release_name
    self.dir = dir_
    self.missing_files = self.get_missing_files()

  def __str__(self):
    return f"{self.distro}/{self.release_name}"

  def file_exists(self, fn):
    return os.path.isfile(f"{self.dir}/{fn}")

  def open_file(self, fn):
    if not self.file_exists(fn):
      raise FileNotFoundError(f"{fn} file was not found for "
                              f"release: {self.release_name} (path={self.dir}/{fn})")
    else:
      return open(f"{self.dir}/{fn}", "rt")

  def get_full_name(self):
    return f"{self.distro}/{self.release_name}"

  def get_version(self):
    with self.open_file(self.VERSION_TXT) as f:
      return f.read().strip()

  def get_symbols(self, filter_list=None):
    symbols = {}
    with self.open_file(self.SYMBOLS_TXT) as f:
      for line in f:
        if line[0] == " ": continue
        [addr, _, name] = line.rstrip().split(" ")
        if not filter_list or name in filter_list:
          symbols[name] = int(addr, 16) - self.KBASE_ADDR
    return symbols

  def get_missing_files(self):
    return [f for f in self.ALL_FILES if not self.file_exists(f)]

  def get_rop_actions(self):
    with self.open_file(self.ROP_ACTIONS_JSON) as f:
      return RopActionSerializer.deserialize(f.read())

  def get_stack_pivots(self):
    with self.open_file(self.STACK_PIVOTS_JSON) as f:
      return PivotSerializer.deserialize(f.read())

  def process(self, config=None):
    version = self.get_version()

    symbol_filter = [s.name for s in config.symbols] if config and config.symbols else None
    symbols = self.get_symbols(symbol_filter)

    rop_actions = self.get_rop_actions()
    if config and config.rop_actions:
      type_ids = [ra.type_id for ra in config.rop_actions]
      rop_actions = [ra for ra in rop_actions if ra.type_id in type_ids]

    stack_pivots = self.get_stack_pivots()
    return Target(distro=self.distro, release_name=self.release_name, version=version,
                  symbols=symbols, rop_actions=rop_actions, stack_pivots=stack_pivots)