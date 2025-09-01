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
    self.symbols_meta = sorted(symbols_meta, key=lambda x: x.name)

  def write_meta(self, wr_meta):
    for (wr, meta) in wr_meta.seekable_list(self.symbols_meta):
      wr.zstr(meta.name)  # name_len + name

  def write_target(self, wr_target, target):
    for meta in self.symbols_meta:
      wr_target.u4(target.symbols.get(meta.name, 0))


class SymbolReader:
  """Helper class to handle symbol reading from the db."""

  def __init__(self):
    self.meta = []

  def read_meta(self, r):
    for _ in r.seekable_list():
      name = r.zstr()
      self.meta.append(SymbolMeta(name))
    return self.meta

  def read_target(self, r):
    return {s.name: r.u4() for s in self.meta}
