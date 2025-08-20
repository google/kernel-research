from typing import Dict, Optional
from pydantic.dataclasses import dataclass

@dataclass
class StructField():
  offset: int
  size: int

@dataclass(unsafe_hash=True)
class Struct():
  size: int
  fields: Dict[str, StructField]
  meta_idx: Optional[int] = None

Structs = Dict[str, Struct]
