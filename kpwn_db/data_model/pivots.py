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

# Pivot classes
from dataclasses import field
from typing import List
from pydantic import TypeAdapter
from pydantic.dataclasses import dataclass

@dataclass
class Pivot:
  address: int
  instructions: List[str]

  def debug_info(self):
    raise NotImplementedError

@dataclass
class StackShift(Pivot):
    """
    This pivot shifts the stack pointer by a specified amount.
    Examples include:
        add rsp, 0x10; ret
        retn 0x10;
    """
    ret_offset: int  # Offset of the return address
    shift_amount: int # The amount by which the stack pointer is shifted]

    def debug_info(self):
        return f"StackShift {hex(self.address)}: {self.ret_offset} {self.shift_amount}\n{self.instructions}"

@dataclass
class OneGadgetPivot(Pivot):
  """
  This pivot doesn't need to be paired with other pivots. 
  Examples include:
      xchg reg, rsp; ret
      mov rsp, reg; ret
      leave; ret
  """
  pivot_reg: str
  used_offsets: List[int]
  next_rip_offset: int

  def debug_info(self):
    return f"OneGadgetPivot {hex(self.address)}: {self.pivot_reg} {self.next_rip_offset}\n{self.instructions}"

@dataclass
class PushIndirectPivot(Pivot):
  """
  This pivot is a push "reg" followed by an indirect control flow transfer such as jmp qword [rsi+0x30].
  Should be paired with a pop rsp pivot
  """
  indirect_type: str
  push_register: str
  used_offsets_in_push: List[int]
  indirect_register: str
  used_offsets_in_indirect_reg: List[int]
  next_rip_offset: int

  def debug_info(self):
    return f"PushIndirectPivot {hex(self.address)}: {self.indirect_type} {self.push_register}" + \
           f"{self.indirect_register} {self.next_rip_offset}\n{self.instructions}"

@dataclass
class PopRspPivot(Pivot):
  """
  This pivot pairs with PushIndirectPivot
  """
  stack_change_before_rsp: int
  next_rip_offset: int

  def debug_info(self):
    return f"PopRspPivot {hex(self.address)}: {self.stack_change_before_rsp} {self.next_rip_offset}\n{self.instructions}"

@dataclass
class Pivots:
  one_gadgets: List[OneGadgetPivot] = field(default_factory=list)
  push_indirects: List[PushIndirectPivot] = field(default_factory=list)
  pop_rsps: List[PopRspPivot] = field(default_factory=list)
  stack_shifts: List[StackShift] = field(default_factory=list)

  def append(self, pivot):
    if isinstance(pivot, OneGadgetPivot):
      self.one_gadgets.append(pivot)
    elif isinstance(pivot, PushIndirectPivot):
      self.push_indirects.append(pivot)
    elif isinstance(pivot, PopRspPivot):
      self.pop_rsps.append(pivot)
    elif isinstance(pivot, StackShift):
      self.stack_shifts.append(pivot)
    else:
      raise ValueError("Unexpected type")

  def combined_list(self):
    return self.one_gadgets + self.push_indirects + self.pop_rsps + self.stack_shifts
