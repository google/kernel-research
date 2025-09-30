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

import re
from typing import Dict, List, Optional
from pydantic.dataclasses import dataclass

@dataclass
class SymbolMeta():
  name: str

@dataclass
class RopActionArg():
  name: str
  required: bool
  default_value: Optional[int] = None

@dataclass
class RopActionMeta():
  desc: str
  args: List[RopActionArg]

  @classmethod
  def from_config(cls, desc: str):
    ARG_PATTERN = r"ARG_([a-z0-9_]+)(?:=(0x[0-9a-fA-F]+|[0-9]+))?"
    args = []
    for name, default_value in re.findall(ARG_PATTERN, desc):
      args.append(RopActionArg(name, not default_value,
        int(default_value, 0) if default_value else None))
    return cls(desc=desc, args=args)

@dataclass
class StructFieldMeta():
  field_name: str
  optional: bool

@dataclass
class StructMeta():
  struct_name: str
  fields: List[StructFieldMeta]

@dataclass
class MetaConfig():
  symbols: List[SymbolMeta]
  rop_actions: List[RopActionMeta]
  structs: List[StructMeta]

  @classmethod
  def from_desc(cls,
                symbols: Dict[int, str] = {},
                rop_actions: List[str] = {},
                structs: Dict[str, List[str]] = {}):
    symbols = [SymbolMeta(name=name) for name in symbols]
    rop_actions = [RopActionMeta.from_config(desc) for desc in rop_actions]

    structs_ = []
    for struct_name, fields in structs.items():
      fields_ = []
      for field_name in fields:
        optional = field_name.endswith("?")
        if optional:
          field_name = field_name[:-1]
        fields_.append(StructFieldMeta(field_name=field_name, optional=optional))
      structs_.append(StructMeta(struct_name=struct_name, fields=fields_))

    return cls(symbols=symbols, rop_actions=rop_actions, structs=structs_)
