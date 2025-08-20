import os

from data_model.db import Db
from data_model.serialization import from_json, to_json
from converter.kpwn_reader import KpwnReader
from converter.kpwn_writer import KpwnWriter
from pydantic import RootModel, TypeAdapter

def dump_yaml(data, f):
  import yaml
  class IndentedDumper(yaml.SafeDumper):
      def increase_indent(self, flow=False, indentless=False):
          return super(IndentedDumper, self).increase_indent(flow, False)
  return yaml.dump(data, f, Dumper=IndentedDumper, default_flow_style=False, sort_keys=False)

def read_kpwn_db(fn):
  _, ext = os.path.splitext(fn)
  match ext:
    case ".kxdb":
      return KpwnReader().read_from_file(fn)
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

def write_kpwn_db(fn, db, indent=None):
  _, ext = os.path.splitext(fn)
  match ext:
    case ".kxdb":
      KpwnWriter(db).write_to_file(fn)
    case ".json":
      with open(fn, "wt") as f:
        f.write(to_json(db, indent=indent))
    case ".yaml":
      data = RootModel[Db](db).model_dump(exclude_none=True)
      with open(fn, "wt") as f:
        dump_yaml(data, f)
    case _:
      raise Exception(f"Unsupported file extension '{ext}'. Only .kxdb, .json and .yaml are supported.")
