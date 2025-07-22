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

"""Classes for writing the kpwn file format."""
import os

from converter.binary_writer import BinaryWriter
from converter.symbols import SymbolWriter
from converter.rop_actions import RopActionWriter
from converter.stack_pivots import StackPivotWriter
from converter.structs import StructWriter

MAGIC = "KPWN"
VERSION_MAJOR = 1
VERSION_MINOR = 1


class KpwnWriter:
  """Class to write the kpwn file format."""

  def __init__(self, db):
    self.symbol_writer = SymbolWriter(db.meta.symbols)
    self.rop_action_writer = RopActionWriter(db.meta.rop_actions)
    self.stack_pivot_writer = StackPivotWriter()
    self.struct_writer = StructWriter(db.meta.structs)
    self.db = db

  def write(self, f, minimal=False):
    wr_root = BinaryWriter(f)
    wr_root.write(bytes(MAGIC, "ascii"))
    wr_root.u2(VERSION_MAJOR)
    wr_root.u2(VERSION_MINOR)

    # meta header
    with wr_root.struct(4) as wr_hdr:
      self.symbol_writer.write_meta(wr_hdr, minimal)
      self.rop_action_writer.write_meta(wr_hdr, minimal)
      self.struct_writer.write_meta(wr_hdr)

    # targets
    wr_root.u4(len(self.db.targets))
    for target in self.db.targets:
      with wr_root.struct(4) as wr_target:
        wr_target.zstr_u2(target.distro)
        wr_target.zstr_u2(target.release_name)
        wr_target.zstr_u2(target.version)

        self.symbol_writer.write_target(wr_target, target)
        self.rop_action_writer.write_target(wr_target, target)
        self.stack_pivot_writer.write_target(wr_target, target)
        self.struct_writer.write_target(wr_target, target)

    # struct layouts
    self.struct_writer.write_struct_layouts(wr_root)

  def write_to_file(self, fn, minimal=False):
    os.makedirs(os.path.abspath(os.path.dirname(fn)), exist_ok=True)
    with open(fn, "wb") as f:
      self.write(f, minimal)
