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

from data_model.pivots import OneGadgetPivot, PushIndirectPivot, PopRspPivot, StackShift, Pivots

REGISTERS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

INDIRECT_TYPES = ["jmp", "call"]

KERNEL_BASE_ADDRESS = 0xffffffff81000000

class StackPivotWriter:
  def write_target(self, wr_target, target):
    with wr_target.struct() as wr:
      def write_int_list(list_):
        for value in wr.list(list_):
          wr.varsint(value)

      def write_address(g):
        wr.varuint(g.address - (KERNEL_BASE_ADDRESS if g.address >= KERNEL_BASE_ADDRESS else 0))

      pivots = target.stack_pivots

      for g in wr.list(pivots.one_gadgets):
        write_address(g)
        wr.varuint(REGISTERS.index(g.pivot_reg))
        write_int_list(g.used_offsets)
        wr.varsint(g.next_rip_offset)

      for g in wr.list(pivots.push_indirects):
        write_address(g)
        wr.varuint(INDIRECT_TYPES.index(g.indirect_type))
        wr.varuint(REGISTERS.index(g.push_register))
        write_int_list(g.used_offsets_in_push)
        wr.varuint(REGISTERS.index(g.indirect_register))
        write_int_list(g.used_offsets_in_indirect_reg)
        wr.varsint(g.next_rip_offset)

      for g in wr.list(pivots.pop_rsps):
        write_address(g)
        wr.varuint(g.stack_change_before_rsp)
        wr.varsint(g.next_rip_offset)

      for g in wr.list(pivots.stack_shifts):
        write_address(g)
        wr.varuint(g.ret_offset)
        wr.varuint(g.shift_amount)

class StackPivotReader:
  def read_target(self, r_target):
    r = r_target.struct()

    def read_int_list():
      result = []
      for _ in r.list():
        result.append(r.varsint())
      return result

    p = Pivots()

    for _ in r.list():
      address = r.varuint()
      pivot_reg = REGISTERS[r.varuint()]
      used_offsets = read_int_list()
      next_rip_offset = r.varsint()
      p.one_gadgets.append(OneGadgetPivot(address, [], pivot_reg, used_offsets, next_rip_offset))

    for _ in r.list():
      address = r.varuint()
      indirect_type = INDIRECT_TYPES[r.varuint()]
      push_register = REGISTERS[r.varuint()]
      used_offsets_in_push = read_int_list()
      indirect_register = REGISTERS[r.varuint()]
      used_offsets_in_indirect_reg = read_int_list()
      next_rip_offset = r.varsint()
      p.push_indirects.append(PushIndirectPivot(address, [], indirect_type, push_register, used_offsets_in_push,
        indirect_register, used_offsets_in_indirect_reg, next_rip_offset))

    for _ in r.list():
      address = r.varuint()
      stack_change_before_rsp = r.varuint()
      next_rip_offset = r.varsint()
      p.pop_rsps.append(PopRspPivot(address, [], stack_change_before_rsp, next_rip_offset))

    for _ in r.list():
      address = r.varuint()
      ret_offset = r.varuint()
      shift_amount = r.varuint()
      p.stack_shifts.append(StackShift(address, [], ret_offset, shift_amount))

    return p

