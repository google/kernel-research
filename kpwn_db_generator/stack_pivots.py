REGISTER_ENUM = {"rax":  0, "rbx":  1, "rcx":  2, "rdx":  3,
                 "rsi":  4, "rdi":  5, "rsp":  6, "rbp":  7,
                 "r8":   8, "r9":   9, "r10": 10, "r11": 11,
                 "r12": 12, "r13": 13, "r14": 14, "r15": 15 }

INDIRECT_TYPE_ENUM = {"jmp": 0, "call": 1}

KERNEL_BASE_ADDRESS = 0xffffffff81000000

class StackPivotWriter:
  def write_target(self, wr_target, target):
    with wr_target.struct() as wr:
      def wr_list(list_):
        wr.varuint(len(list_))
        return list_

      def write_int_list(list_):
        for value in wr_list(list_):
          wr.varsint(value)

      def write_address(g):
        wr.varuint(g.address - (KERNEL_BASE_ADDRESS if g.address >= KERNEL_BASE_ADDRESS else 0))

      pivots = target.get_stack_pivots()

      for g in wr_list(pivots.one_gadgets):
        write_address(g)
        wr.varuint(REGISTER_ENUM[g.pivot_reg])
        write_int_list(g.used_offsets)
        wr.varsint(g.next_rip_offset)

      for g in wr_list(pivots.push_indirects):
        write_address(g)
        wr.varuint(INDIRECT_TYPE_ENUM[g.indirect_type])
        wr.varuint(REGISTER_ENUM[g.push_register])
        write_int_list(g.used_offsets_in_push)
        wr.varuint(REGISTER_ENUM[g.indirect_register])
        write_int_list(g.used_offsets_in_indirect_reg)
        wr.varsint(g.next_rip_offset)

      for g in wr_list(pivots.pop_rsps):
        write_address(g)
        wr.varuint(g.stack_change_before_rsp)
        wr.varsint(g.next_rip_offset)
