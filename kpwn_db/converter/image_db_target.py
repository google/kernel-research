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

"""Processes per-target files from kernel-image-db folders."""
import os
from data_model.db import Target
from data_model.pivots import Pivots
from data_model.rop_chain import RopActions
from data_model.structs import Structs
from data_model.serialization import from_json

class ImageDbTarget:
  """Processes per-target files from kernel-image-db folders."""

  KBASE_ADDR = 0xffffffff81000000
  VERSION_TXT = "version.txt"
  SYMBOLS_TXT = "symbols.txt"
  ROP_ACTIONS_JSON = "rop_actions.json"
  STACK_PIVOTS_JSON = "stack_pivots.json"
  STRUCTS_JSON = "structs.json"
  ALL_FILES = [VERSION_TXT, SYMBOLS_TXT, ROP_ACTIONS_JSON, STACK_PIVOTS_JSON, STRUCTS_JSON]

  def __init__(self, distro, release_name, dir_):
    self.distro = distro
    self.release_name = release_name
    self.dir = dir_
    self.missing_files = self.get_missing_files()
    self.allow_partial = False

  def __str__(self):
    return f"{self.distro}/{self.release_name}"

  def file_exists(self, fn):
    return os.path.isfile(f"{self.dir}/{fn}")

  def read_file(self, fn):
    if self.file_exists(fn):
      with open(f"{self.dir}/{fn}", "rt") as f:
        return f.read()

    if self.allow_partial:
      return None

    raise FileNotFoundError(f"{fn} file was not found for "
                            f"release: {self.release_name} (path={self.dir}/{fn})")

  def get_full_name(self):
    return f"{self.distro}/{self.release_name}"

  def get_missing_files(self):
    return [f for f in self.ALL_FILES if not self.file_exists(f)]

  def get_version(self):
    version = self.read_file(self.VERSION_TXT)
    return version.strip() if version else None

  def get_symbols(self, filter_list=None):
    content = self.read_file(self.SYMBOLS_TXT)
    if content is None: return None

    symbols = {}
    for line in content.split("\n"):
      if not line or line.startswith(" "): continue
      [addr, _, name] = line.rstrip().split(" ")
      if not filter_list or name in filter_list:
        symbols[name] = int(addr, 16) - self.KBASE_ADDR
    return symbols

  def from_json(self, fn, type_):
    json_str = self.read_file(fn)
    return from_json(type_, json_str) if json_str else None

  def get_rop_actions(self):
    return self.from_json(self.ROP_ACTIONS_JSON, RopActions)

  def get_stack_pivots(self):
    return self.from_json(self.STACK_PIVOTS_JSON, Pivots)

  def get_structs(self):
    return self.from_json(self.STRUCTS_JSON, Structs)

  def process_symbols(self, config=None):
    symbol_filter = [s.name for s in config.symbols] if config and config.symbols else None
    return self.get_symbols(symbol_filter)

  def process_rop_actions(self, config=None):
    rop_actions = self.get_rop_actions()
    if rop_actions and config and config.rop_actions:
      type_ids = [ra.type_id for ra in config.rop_actions]
      rop_actions = [ra for ra in rop_actions if ra.type_id in type_ids]
    return rop_actions

  def process_structs(self, config=None, allow_missing=False):
    all_structs = self.get_structs()
    if all_structs is None or not config or not config.structs: return all_structs

    structs = {}
    for struct_meta in config.structs:
      struct = all_structs.get(struct_meta.struct_name)
      if not struct:
        if not allow_missing:
          raise RuntimeError(f"Struct '{struct_meta.struct_name}' not found for target: {self.get_full_name()}")
        continue

      structs[struct_meta.struct_name] = struct
      missing_fields = [f.field_name for f in struct_meta.fields if not f.optional and not struct.fields.get(f.field_name)]
      if missing_fields and not allow_missing:
        raise RuntimeError(f"Missing fields ('{', '.join(missing_fields)}') for struct '{struct_meta.struct_name}' for target: {self.get_full_name()}")

    return structs

  def process(self, config=None, allow_partial=False, allow_missing=False):
    self.allow_partial = allow_partial
    version = self.get_version()
    symbols = self.process_symbols(config)
    rop_actions = self.process_rop_actions(config)
    stack_pivots = self.get_stack_pivots()
    structs = self.process_structs(config, allow_missing)
    return Target(distro=self.distro, release_name=self.release_name, version=version,
                  symbols=symbols, rop_actions=rop_actions, stack_pivots=stack_pivots,
                  structs=structs)
