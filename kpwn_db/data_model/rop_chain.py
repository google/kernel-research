from typing import List, Union, Optional
from pydantic import TypeAdapter
from pydantic.dataclasses import dataclass
from dataclasses import field

@dataclass
class RopChainItem():
  pass

@dataclass
class RopChainConstant(RopChainItem):
  value: int

@dataclass
class RopChainOffset(RopChainItem):
  kernel_offset: int
  description: Optional[str] = None

  def __repr__(self) -> str:
    return f"RopChainOffset(kernel_offset={hex(self.kernel_offset)})"

@dataclass
class RopChainArgument(RopChainItem):
  argument_index: int

@dataclass
class RopAction():
  type_id: int
  description: Optional[str] = None
  gadgets: List[Union[RopChainConstant, RopChainOffset, RopChainArgument]] = field(default_factory=list)

RopActions = List[RopAction]
