"""Module containing classes related to targets."""
from typing import Dict, List, Optional
from pydantic.dataclasses import dataclass
from .meta import MetaConfig
from .pivots import Pivots
from .rop_chain import RopActions
from .structs import Structs

@dataclass
class Target():
  distro: str
  release_name: str
  version: Optional[str]
  symbols: Optional[Dict[str, int]]  # name -> offset
  rop_actions: Optional[RopActions]
  stack_pivots: Optional[Pivots]
  structs: Optional[Structs]

  def __str__(self):
    return f"{self.distro}/{self.release_name}"

@dataclass
class Db():
  meta: MetaConfig
  targets: List[Target]
