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
  description: Optional[str] = None
  gadgets: List[Union[RopChainConstant, RopChainOffset, RopChainArgument]] = field(default_factory=list)

RopActions = List[RopAction]
