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

import os

from data_model.db import Db
from data_model.serialization import from_json, to_json
from converter.kxdb_reader import KxdbReader
from converter.kxdb_writer import KxdbWriter
from pydantic import RootModel, TypeAdapter

def dump_yaml(data, f):
  import yaml
  class IndentedDumper(yaml.SafeDumper):
      def increase_indent(self, flow=False, indentless=False):
          return super(IndentedDumper, self).increase_indent(flow, False)
  return yaml.dump(data, f, Dumper=IndentedDumper, default_flow_style=False, sort_keys=False)

def read_kxdb(fn):
  _, ext = os.path.splitext(fn)
  match ext:
    case ".kxdb":
      return KxdbReader().read_from_file(fn)
    case ".json":
      with open(fn, "rt") as f:
        return from_json(Db, f.read())
    case ".yaml":
      with open(fn, "rt") as f:
        import yaml
        obj = yaml.safe_load(f)
        return TypeAdapter(Db).validate_python(obj)
    case _:
      raise Exception(f"Unsupported file extension '{ext}'. Only .kxdb, .json and .yaml are supported.")

def write_kxdb(fn, db, indent=None):
  _, ext = os.path.splitext(fn)
  match ext:
    case ".kxdb":
      KxdbWriter(db).write_to_file(fn)
    case ".json":
      with open(fn, "wt") as f:
        f.write(to_json(db, indent=indent))
    case ".yaml":
      data = RootModel[Db](db).model_dump(exclude_none=True)
      with open(fn, "wt") as f:
        dump_yaml(data, f)
    case _:
      raise Exception(f"Unsupported file extension '{ext}'. Only .kxdb, .json and .yaml are supported.")
