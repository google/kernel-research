import re
from typing import Dict, List, Optional
from pydantic.dataclasses import dataclass

@dataclass
class SymbolMeta():
  type_id: int
  name: str

@dataclass
class RopActionArg():
  name: str
  required: bool
  default_value: Optional[int] = None

@dataclass
class RopActionMeta():
  type_id: int
  desc: str
  args: List[RopActionArg]

  @classmethod
  def from_config(cls, type_id: int, desc: str):
    ARG_PATTERN = r"ARG_([a-z0-9_]+)(?:=(0x[0-9a-fA-F]+|[0-9]+))?"
    args = []
    for name, default_value in re.findall(ARG_PATTERN, desc):
      args.append(RopActionArg(name, not default_value,
        int(default_value, 0) if default_value else None))
    return cls(type_id=type_id, desc=desc, args=args)

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
                rop_actions: Dict[int, str] = {},
                structs: Dict[str, List[str]] = {}):
    symbols = [
        SymbolMeta(type_id=type_id, name=name)
        for type_id, name in symbols.items()
    ]
    rop_actions = [
        RopActionMeta.from_config(type_id, desc)
        for type_id, desc in rop_actions.items()
    ]

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
