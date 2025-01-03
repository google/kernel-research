"""Module containing classes related to targets."""
from typing import Dict, List
from .meta import MetaConfig
from .pivots import Pivots
from .rop_chain import RopActions
from pydantic.dataclasses import dataclass

@dataclass
class Target():
  distro: str
  release_name: str
  version: str
  symbols: Dict[str, int]  # name -> offset
  rop_actions: RopActions
  stack_pivots: Pivots

  def __str__(self):
    return f"{self.distro}/{self.release_name}"

@dataclass
class Db():
  meta: MetaConfig
  targets: List[Target]
