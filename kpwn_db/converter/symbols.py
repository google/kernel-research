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

from data_model.meta import SymbolMeta

class SymbolWriter:
  """Helper class to handle symbol writing to the db."""

  def __init__(self, symbols_meta):
    self.symbols_meta = symbols_meta

  def write_meta(self, wr_hdr, minimal=False):
    wr_hdr.u4(len(self.symbols_meta))
    for meta in self.symbols_meta:
      with wr_hdr.struct() as wr_struct:
        wr_struct.u4(meta.type_id)    # type_id
        if minimal:
          continue
        wr_struct.zstr_u2(meta.name)  # name_len + name

  def write_target(self, wr_target, target):
    for meta in self.symbols_meta:
      wr_target.u4(target.symbols.get(meta.name, 0))


class SymbolReader:
  """Helper class to handle symbol reading from the db."""

  def __init__(self):
    self.meta = []

  def read_meta(self, reader):
    len_ = reader.u4()
    for _ in range(len_):
      r = reader.struct()
      type_id = r.u4()
      name = r.zstr_u2()
      self.meta.append(SymbolMeta(type_id, name))
    return self.meta

  def read_target(self, reader):
    return {s.name: reader.u4() for s in self.meta}
