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
  default_value: Optional[int] = None
  required: bool = True  # Calculated field

  # Post-init to set required based on default_value
  def __init__(self, **data):
    super().__init__(**data)
    self.required = self.default_value is None

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
      args.append(
          RopActionArg(
              name=name,
              default_value=int(default_value, 0) if default_value else None))
    return cls(type_id=type_id, desc=desc, args=args)

@dataclass
class MetaConfig():
  symbols: List[SymbolMeta]
  rop_actions: List[RopActionMeta]

  @classmethod
  def from_desc(cls,
                symbols: Dict[int, str] = {},
                rop_actions: Dict[int, str] = {}):
    symbols_meta = [
        SymbolMeta(type_id=type_id, name=name)
        for type_id, name in symbols.items()
    ]
    rop_actions_meta = [
        RopActionMeta.from_config(type_id, desc)
        for type_id, desc in rop_actions.items()
    ]
    return cls(symbols=symbols_meta, rop_actions=rop_actions_meta)
