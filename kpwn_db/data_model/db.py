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
