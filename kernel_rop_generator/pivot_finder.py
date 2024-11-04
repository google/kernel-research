import logging
import re
import sys
from collections import defaultdict
import archinfo
import gadget_finder


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class BadPivot(Exception):
    """Exception raised for a bad pivot."""


# size for the rop gadget search
CONTEXT_SIZE = 5

# div can cause floating point exceptions so don't use it
# push is disallowed other than what we look for in the patterns
# Below are the allowlisted instructions that are safe to use in pivot gadgets

# Instructions that don't clobber any arguments
CLOBBER_ZERO = ["cmp", "test",                                     # test
                "nop",                                             # nop
                ]

# Instructions that clobber one argument
CLOBBER_ONE = ["add", "sub", "inc", "dec", "neg", "adc", "sbb",        # basic arith
               "lea",                                                  # advanced arith
               "and", "or", "xor", "not",                              # bitwise arith
               "shl", "sal", "shr", "sar", "lsl", "lsr",               # shifts
               "rol", "ror", "rcl", "rcr",                             # rotates
               "bswap",                                                # other bit stuff
               "mov", "movsx", "movzx", "movsxd",                      # mov
               "cmovl", "cmovene", "cmovo", "cmovns", "cmove",         # cmov
               "pop",                                                  # stack shift track needed
               ]

# Instructions that clobber two arguments
CLOBBER_TWO = ["xchg"]


SINGLE_INSTRUCTION_PIVOT_PATTERNS = [
    r"xchg\s+(\w+),\s*rsp", r"xchg\s+rsp,\s*(\w+)", r"mov\s+rsp,\s*(\w+)", r"leave"]
PUSH_PATTERN = r"push\s+(\w+)"
POP_PATTERN = r"pop\s+(\w+)"

BASE_REGISTER_NAMES = [
    'rax', 'rbx', 'rcx', 'rdx',
    'rdi', 'rsi',
    'rip', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]

PIVOT_REGISTER_NAMES = [
    'rax', 'rbx', 'rcx', 'rdx',
    'rdi', 'rsi',
    'rbp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]

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


class PivotFinder:
    def __init__(self, vmlinux_path) -> None:
        self.vmlinux_path = vmlinux_path
        self._reg_to_base_reg = {}
        self._setup_reg_info()
        self.pivots = []

    def find_pivots(self):
        """
        finds all the pivots
        """
        gadgets = gadget_finder.find_gadgets(self.vmlinux_path, CONTEXT_SIZE)
        for addr, gadget in gadgets.items():
            try:
                self.pivots.append(self._check_if_pivot(addr, gadget))
            except BadPivot as e:
                logger.debug(
                    'Gadget: %s was a bad pivot with reason: %s', gadget, e)

        return self.pivots

    # functions for preparing register info

    def _setup_reg_info(self):
        """
        Creates a mapping of sub registers to main register. 
        For example eax, ax, al, ah.. etc are mapped to rax as the base register. 
        We use this mapping to track which base register was read/written to 
        rather than tracking sub registers.
        """
        reg_to_base_reg = {}

        # for each register find the base register name and store in a dictionary
        arch = archinfo.ArchAMD64()
        for reg, (offset, _) in arch.registers.items():
            base_reg_off_size = arch.get_base_register(offset)
            base_reg_name = arch.register_size_names[base_reg_off_size]
            if base_reg_name in BASE_REGISTER_NAMES:
                reg_to_base_reg[reg] = base_reg_name

        self._reg_to_base_reg = reg_to_base_reg

    # instruction parsing

    def _split_instruction(self, instruction):
        # Split the instruction at the first space to separate the opcode from the operands
        parts = instruction.strip().split(' ', 1)
        opcode = parts[0]
        operands_list = parts[1].split(',') if len(parts) > 1 else []

        # Strip whitespace around operands to clean up the list
        operands_list = [operand.strip() for operand in operands_list]
        return opcode, operands_list

    def _get_base_reg(self, reg_name):
        return self._reg_to_base_reg[reg_name]

    def _get_operands_written_to(self, opcode, operands):
        """
        Returns the operands that are written to by the instruction

        Example:
            mov [rax+8], rbx -> ["[rax+8]"]
            xchg eax, esi -> ["eax", "esi"]
            nop -> []
        """
        num_operands_clobbered = 0
        if opcode in CLOBBER_ZERO:
            num_operands_clobbered = 0
        elif opcode in CLOBBER_ONE:
            num_operands_clobbered = 1
        elif opcode in CLOBBER_TWO:
            num_operands_clobbered = 2
        else:
            assert f"Unhandled opcode {opcode}"

        return operands[:num_operands_clobbered]

    def _is_tracked_reg(self, operand):
        return operand in self._reg_to_base_reg

    def _get_clobbered_regs(self, opcode, operands):
        """
        Returns the list of clobbered registers.
        """
        clobbered_operands = self._get_operands_written_to(opcode, operands)
        clobbered_regs = []
        for operand in clobbered_operands:
            if '[' in operand:
                # Skip memory writes
                # Ex: mov [rax+8], rbx
                pass
            # Add the base register if we have it, otherwise the original register
            elif operand in self._reg_to_base_reg:
                clobbered_regs.append(self._reg_to_base_reg[operand])
            else:
                clobbered_regs.append(operand)
        return clobbered_regs

    def _get_memory_reads_and_writes(self, opcode, operands):
        """
        Returns dicts of memory_reads and memory_writes for an instruction
        Dictionary format:
        Key : register
        Value : Set of offsets

        Example:
        [rax+8] -> {"rax": {8}}
        """
        memory_reads = defaultdict(set)
        memory_writes = defaultdict(set)
        written_to_operands = self._get_operands_written_to(opcode, operands)

        for operand in operands:
            if '[' in operand:
                reg, offset = self._parse_memory_reg_and_offset(operand)
                try:
                    offset = int(offset, 0)
                except ValueError:
                    # offset isn't an integer
                    # operands like [rax+rbx] not handled due to complexity
                    raise BadPivot("Invalid offset") from None
                # store memory read/write offset
                if operand in written_to_operands:
                    memory_writes[reg].add(offset)
                else:
                    memory_reads[reg].add(offset)

        return memory_reads, memory_writes

    def _parse_memory_reg_and_offset(self, operand):
        # Pattern to find and parse an operand with optional decimal or hexadecimal offsets within brackets
        pattern = r"\[(\w+)([+-].+?)?\]"
        match = re.search(pattern, operand)
        if match:
            register = match.group(1)
            offset = match.group(2) if match.group(2) else "0"
            # constant addresses are bad
            if register.startswith("0x"):
                raise BadPivot("constant memory reference")
            return register, offset
        else:
            raise BadPivot("memory addr unknown")

    def _parse_jmp_or_call_instruction(self, inst):
        # Pattern to match various jmp formats, optionally including 'qword'
        pattern = r"(?:call|jmp)\s+(qword\s+)?\[(\w+)([+-](?:0x[\da-fA-F]+|\d+))?\]"
        match = re.match(pattern, inst)
        if match:
            # Register is captured in the second group
            register = match.group(2)

            # Offset value, if present, is captured in the third group
            offset = match.group(3) if match.group(3) else "0"

            # offset should be an integer
            try:
                offset = int(offset, 0)
            except ValueError:
                raise BadPivot("Offset isn't an int") from None

            return register, offset
        else:
            raise BadPivot("jump addr unknown")

    # instruction analysis functions
    def _check_no_push_pop(self, insts):
        """
        checks that there are no push/pop in insts
        """
        for inst in insts:
            if re.match(PUSH_PATTERN, inst):
                raise BadPivot("push not allowed here")
            if re.match(POP_PATTERN, inst):
                raise BadPivot("pop not allowed here")

    def _compute_stack_change(self, insts):
        """
        returns the stack change
        """
        # TODO maybe we want to allow "add rsp"
        # but add rsp seems quite rare in the pivots it would be okay in
        change = 0
        for inst in insts:
            if re.match(POP_PATTERN, inst):
                change += 8
        return change

    def _check_opcode(self, opcode):
        if opcode in CLOBBER_ZERO:
            return

        if opcode in CLOBBER_ONE:
            return

        if opcode in CLOBBER_TWO:
            return

        raise BadPivot("opcode not in allowlist")

    def _analyze_instruction_reads_writes(self, instructions, non_modify_regs, memory_regs):
        """
        Checks instructions in allowlist, which registers and memory are written to
        instructions should not change the non_modify_regs
        instructions may read/write to memory near memory_regs

        Does not save the size of writes. 
        Assume all writes are 8 bytes long to overapproximate.

        Returns:
          A dictionary of memory writes where keys are registers and values are sets of offsets.
        """
        # TODO reads/writes relative to rip could be okay, check permissions
        clobbered_regs = set()
        memory_writes = defaultdict(set)
        memory_reads = defaultdict(set)

        for instruction in instructions:
            opcode, operands = self._split_instruction(instruction)

            # check if instruction is not in the benign allowlist
            self._check_opcode(opcode)

            # collect clobbered regs
            clobbered_regs.update(self._get_clobbered_regs(opcode, operands))

            # collect memory reads/writes
            inst_reads, inst_writes = self._get_memory_reads_and_writes(
                opcode, operands)

            # memory writes/reads to a clobbered reg are not okay
            # Case when rbx is not clobbered
            # push rbx ; or byte [rbx+0x41], bl ; pop rsp ; pop rbp ; ret ;
            # Case when rbx is clobbered
            # push rbx ; xor ebx, ecx ; or byte [rbx+0x41], bl ; pop rsp ; pop rbp ; ret ;

            for reg in inst_writes.keys():
                if reg in clobbered_regs:
                    raise BadPivot("memory write to clobbered reg")
            for reg in inst_reads.keys():
                if reg in clobbered_regs:
                    raise BadPivot("memory read from clobbered reg")

            for reg, offs in inst_writes.items():
                memory_writes[reg].update(offs)
            for reg, offs in inst_reads.items():
                memory_reads[reg].update(offs)

        # check if we touched a reg we shouldn't
        if clobbered_regs & non_modify_regs:
            raise BadPivot("Clobbers an important register")

        # check we only changed registers in the PIVOT_REGISTER_NAMES
        # some of the other ones such as xmm registers could be okay
        # but it's easiest to just check this allowlist
        if not clobbered_regs.issubset(set(PIVOT_REGISTER_NAMES)):
            raise BadPivot("overwriting rgister not in allowlist")

        # check r/w addresses are only to memory_regs and do not write less than 0 or more than 0x80
        # range is chosen arbitrarily to keep reads and writes within writable memory
        for reg, offs in memory_writes.items():
            if reg not in memory_regs:
                raise BadPivot("memory write with non-allowed register")
            for off in offs:
                if off < 0 or off > 0x80:
                    # TODO: Should we allow negative offsets?
                    raise BadPivot("memory write offset outside allowed range")
        for reg in memory_reads:
            if reg not in memory_regs:
                raise BadPivot("memory read with non-allowed register")
            for off in offs:
                if off < 0 or off > 0x80:
                    raise BadPivot("memory read offset outside allowed range")

        return memory_writes

    def _check_write_collision_with_rip_offset(self, write_offsets, rip_offset):
        write_offsets = set(write_offsets)

        # check memory writes do not collide with next rip offset
        rip_offset_range = set(range(rip_offset-7, rip_offset+7))

        if rip_offset_range & write_offsets:
            raise BadPivot("Memory write collides with next rip")

    def _try_match_poprsp_pivot(self, address, gadget):
        """
        After finding a gadget which starts with a pop
        checks if the gadget is a valid pop rsp gadget (with other pops possibly before and after)

        Tracks stack change before and after the pop rsp

        pop rsp; pop rax; ret (0 stack change before, 8 stack change after)
        pop rax; pop rsp; pop rax; ret (8 stack change before 8 stack change after)
        """
        last_inst = gadget[-1]
        if gadget.count("pop rsp") == 1 and last_inst == "ret":
            # all instructions should be pop
            insts_before_ret = gadget[:-1]
            if all(re.match(POP_PATTERN, inst) for inst in insts_before_ret):
                idx = insts_before_ret.index("pop rsp")
                stack_change_before = idx*8
                stack_change_after = (len(insts_before_ret)-1-idx)*8

                return PopRspPivot(address, gadget, stack_change_before, stack_change_after)

        raise BadPivot("doesn't match poprsp")

    def _parse_single_inst_pivot(self, address, gadget, match):
        """
        After finding a matching pattern with a single instruction which includes the patterns below
        xchg reg, rsp; ret
        mov rsp, reg; ret
        leave; ret

        Checks the middle instructions to make sure they are allowlisted safe ones
        Analyzes memory reads and writes and creates the Pivot
        """
        first_inst = gadget[0]
        last_inst = gadget[-1]
        middle_insts = gadget[1:-1]

        if first_inst == "leave":
            pivot_reg = "rbp"
        else:
            pivot_reg = match.group(1)

        if pivot_reg not in PIVOT_REGISTER_NAMES:
            raise BadPivot("pivot_reg isn't a allowlisted Pivot register")

        # last inst should be a ret
        if last_inst != "ret":
            raise BadPivot(
                "Gadgets for single pivot instructions should end in a ret")

        # for this gadget we can have reads/writes to pivot_reg because
        # pivot reg will point to readable/ writable memory so won't crash
        memory_writes = self._analyze_instruction_reads_writes(
            middle_insts,
            {"rsp"},  # rsp should not be modified
            {pivot_reg}  # can read/write to memory pointed by pivot reg
        )

        stack_change = self._compute_stack_change(middle_insts)

        # Adjust the stack to handle the stack change in leave instruction
        if first_inst == "leave":
            stack_change += 8

        # in the xchg case, we don't need to track memory writes to the pivot reg
        # because it points at the old stack
        if first_inst.startswith("xchg"):
            used_offsets = []
        else:
            used_offsets = list(memory_writes[pivot_reg])

        return OneGadgetPivot(address, gadget, pivot_reg, used_offsets, stack_change)

    def _try_match_push_poprsp_pivot(self, address, gadget, pivot_reg):
        """
        After finding a gadget with includes the following pattern 
        push reg ; ... ; pop rsp ; ... ; ret ;  

        Checks the middle instructions to make sure they are allowlisted safe ones
        Analyzes memory reads and writes and creates the Pivot
        """
        last_inst = gadget[-1]
        middle_insts = gadget[1:-1]

        # check if it's a push ... pop rsp ... ret
        if last_inst != "ret":
            raise BadPivot("push poprsp should end in ret")
        if middle_insts.count("pop rsp") != 1:
            raise BadPivot("should have exactly one pop rsp")

        idx = middle_insts.index("pop rsp")

        # for this gadget we can have reads/writes to pivot_reg
        memory_writes = self._analyze_instruction_reads_writes(
            middle_insts[:idx] + middle_insts[idx+1:],  # skip pop rsp
            {"rsp"},  # rsp should not be modified
            {pivot_reg}  # can read/write to pivot reg
        )

        # we should have no push or pop before the pop rsp
        self._check_no_push_pop(middle_insts[:idx])

        stack_change = self._compute_stack_change(middle_insts[idx+1:])

        used_offsets = list(memory_writes[pivot_reg])

        self._check_write_collision_with_rip_offset(used_offsets, stack_change)

        return OneGadgetPivot(address, gadget, pivot_reg, used_offsets, stack_change)

    def _try_match_indirect_pivot(self, address, gadget, pivot_reg):
        """
        After finding a gadget with includes the following pattern 
        push reg ; ... ;  jmp qword [reg+offset];

        Checks the middle instructions to make sure they are allowlisted safe ones
        Analyzes memory reads and writes and creates the Pivot
        """
        last_inst = gadget[-1]
        middle_insts = gadget[1:-1]

        # make sure no push or pop after the first push
        self._check_no_push_pop(middle_insts)

        jump_reg, offset = self._parse_jmp_or_call_instruction(last_inst)
        if jump_reg not in PIVOT_REGISTER_NAMES:
            raise BadPivot("jump register not allowlisted")

        if offset < 0 or offset >= 0x80:
            raise BadPivot("jump gadget has large offset")

        # for this gadget we can have reads/writes to pivot_reg or jump_reg
        # TODO: check if allowing these helps or we can simplify
        memory_writes = self._analyze_instruction_reads_writes(
            middle_insts,
            {"rsp", jump_reg},  # rsp/jump_reg should not be modified
            {pivot_reg, jump_reg}  # can read/write to pivot_reg or jump_reg
        )

        # check memory writes[jump_reg] don't overlap jump offset
        jump_used_offsets = list(memory_writes[jump_reg])

        self._check_write_collision_with_rip_offset(
            jump_used_offsets, offset)

        indirect_type = last_inst.split(" ")[0]

        return PushIndirectPivot(address, gadget, indirect_type, pivot_reg, memory_writes[pivot_reg],
                                 jump_reg, jump_used_offsets, offset)

    def _check_if_pivot(self, address, gadget):
        """
        Checks if the gadget matches one of our pivot patterns.

        xchg reg, rsp; ret
        mov rsp, reg; ret
        leave; ret
        push reg; … ; pop rsp; ret
        push reg; jmp qword [reg + const]
        [pops]; pop rsp; [pops]; ret

        For all of the above patterns we check if the first instruction matches the pattern except 
        for the "pop rsp" pattern because that instruction could be in the middle.
        """
        first_inst = gadget[0]
        last_inst = gadget[-1]

        # check if first instruction is a single pivot instruction
        for pattern in SINGLE_INSTRUCTION_PIVOT_PATTERNS:
            match = re.match(pattern, first_inst)
            if match:
                return self._parse_single_inst_pivot(address, gadget, match)

        # multiple patterns match if first_instruction is a push reg
        match = re.match(PUSH_PATTERN, first_inst)
        if match:
            pivot_reg = match.group(1)
            if pivot_reg not in PIVOT_REGISTER_NAMES:
                raise BadPivot("push not good register for pivot")

            # check if push ... pop rsp ... ret
            if gadget.count("pop rsp") == 1:
                return self._try_match_push_poprsp_pivot(address, gadget, pivot_reg)

            # check if push ... jump|call [reg]
            if last_inst.startswith("jmp") or last_inst.startswith("call"):
                return self._try_match_indirect_pivot(address, gadget, pivot_reg)

        # check if [popN, poprsp, popN ret]
        if re.match(POP_PATTERN, first_inst):
            return self._try_match_poprsp_pivot(address, gadget)

        raise BadPivot("no match")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    pivot_finder = PivotFinder(binary_path)
    pivots = pivot_finder.find_pivots()

    for pivot in pivots:
        pivot.debug_print()
        print("")
