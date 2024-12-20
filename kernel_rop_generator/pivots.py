# Pivot classes

class Pivot:
    def __init__(self, address, instructions):
        self.address = address
        self.instructions = instructions

    def debug_print(self):
        raise NotImplementedError


class OneGadgetPivot(Pivot):
    """
    This pivot doesn't need to be paired with other pivots. 
    Examples include:
        xchg reg, rsp; ret
        mov rsp, reg; ret
        leave; ret
    """

    def __init__(self, address, instructions, pivot_reg, used_offsets, next_rip_offset):
        super().__init__(address, instructions)
        self.pivot_reg = pivot_reg
        self.used_offsets = used_offsets
        self.next_rip_offset = next_rip_offset

    def debug_print(self):
        print("OneGadgetPivot: ", self.pivot_reg, self.next_rip_offset)
        print(self.instructions)


class PushIndirectPivot(Pivot):
    """
    This pivot is a push "reg" followed by an indirect control flow transfer such as jmp qword [rsi+0x30].
    Should be paired with a pop rsp pivot
    """

    def __init__(self, address, instructions, indirect_type, push_register, used_offsets_in_push,
                 indirect_register, used_offsets_in_indirect_reg, next_rip_offset):
        super().__init__(address, instructions)
        self.indirect_type = indirect_type
        self.push_register = push_register
        self.used_offsets_in_push = used_offsets_in_push
        self.indirect_register = indirect_register
        self.used_offsets_in_indirect_reg = used_offsets_in_indirect_reg
        self.next_rip_offset = next_rip_offset

    def debug_print(self):
        print("PushIndirectPivot: ", self.indirect_type, self.push_register,
              self.indirect_register, self.next_rip_offset)
        print(self.instructions)


class PopRspPivot(Pivot):
    """
    This pivot pairs with PushIndirectPivot
    """

    def __init__(self, address, instructions, stack_change_before_rsp, next_rip_offset):
        super().__init__(address, instructions)
        self.stack_change_before_rsp = stack_change_before_rsp
        self.next_rip_offset = next_rip_offset

    def debug_print(self):
        print("PopRspPivot: ", self.stack_change_before_rsp, self.next_rip_offset)
        print(self.instructions)

class Pivots:
    def __init__(self, one_gadgets=None, push_indirects=None, pop_rsps=None):
        self.one_gadgets = one_gadgets or []
        self.push_indirects = push_indirects or []
        self.pop_rsps = pop_rsps or []

    def append(self, pivot):
        if isinstance(pivot, OneGadgetPivot):
            self.one_gadgets.append(pivot)
        elif isinstance(pivot, PushIndirectPivot):
            self.push_indirects.append(pivot)
        elif isinstance(pivot, PopRspPivot):
            self.pop_rsps.append(pivot)

    def combined_list(self):
        return self.one_gadgets + self.push_indirects + self.pop_rsps
