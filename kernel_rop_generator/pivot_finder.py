import argparse
import logging
import re
import sys
from collections import defaultdict
import archinfo
import gadget_finder
from pivots import *
from pivot_serializer import PivotSerializer

from rop_util import setup_logger

logger = setup_logger("pivot_finder")
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


class PivotFinder:
    def __init__(self, rop_gadget_backend) -> None:
        self.rop_gadget_backend = rop_gadget_backend
        self._reg_to_base_reg = {}
        self._setup_reg_info()
        self.pivots = Pivots()

    def find_pivots(self):
        """
        Finds all the pivots
        """
        gadgets = gadget_finder.find_gadgets(self.rop_gadget_backend)
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
            raise ValueError(f"Unhandled opcode {opcode}")

        return operands[:num_operands_clobbered]

    def _get_clobbered_regs(self, opcode, operands):
        """
        Returns the list of clobbered registers.

        Callers should check we are only writing to general purpose registers. 
        Writes to certain registers such as fs and gs can cause crashes
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
            if '[' not in operand:
                continue
            reg, offset = self._parse_memory_reg_and_offset(operand)
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
                raise BadPivot("Constant memory reference, value is not a register")
            # convert offset to int
            try:
                offset = int(offset, 0)
            except ValueError:
                # offset isn't an integer
                # operands like [rax+rbx] not handled due to complexity
                raise BadPivot("Invalid offset") from None
            return register, offset
        else:
            raise BadPivot("Memory addr unknown")

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
            raise BadPivot("Address unknown for jmp or call instruction")

    # instruction analysis functions
    def _check_no_push_pop(self, insts):
        """
        Checks that there are no push/pop in insts
        """
        for inst in insts:
            if re.match(PUSH_PATTERN, inst):
                raise BadPivot("push not allowed here")
            if re.match(POP_PATTERN, inst):
                raise BadPivot("pop not allowed here")

    def _compute_stack_change(self, insts):
        """
        Returns the stack change
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

        raise BadPivot("Opcode not in allowlist")

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
                    raise BadPivot("Memory write to clobbered reg")
            for reg in inst_reads.keys():
                if reg in clobbered_regs:
                    raise BadPivot("Memory read from clobbered reg")

            for reg, offsets in inst_writes.items():
                memory_writes[reg].update(offsets)
            for reg, offsets in inst_reads.items():
                memory_reads[reg].update(offsets)

        # check if we touched a reg we shouldn't
        if clobbered_regs & non_modify_regs:
            raise BadPivot("Clobbers an important register")

        # check we only changed registers in the PIVOT_REGISTER_NAMES
        # some of the other ones such as xmm registers could be okay
        # but it's easiest to just check this allowlist
        if not clobbered_regs.issubset(set(PIVOT_REGISTER_NAMES)):
            raise BadPivot("Overwriting rgister not in allowlist")

        # check r/w addresses are only to memory_regs and do not write less than 0 or more than 0x80
        # range is chosen arbitrarily to keep reads and writes within writable memory
        def check_access(memory_accesses, op_type):
            for reg, offsets in memory_accesses.items():
                if reg not in memory_regs:
                    raise BadPivot(f"Memory {op_type} with non-allowed register")
                for offset in offsets:
                    if offset < 0 or offset > 0x80:
                        # These offsets are arbitrary
                        raise BadPivot(
                            f"Memory {op_type} offset outside allowed range")

        check_access(memory_writes, "write")
        check_access(memory_reads, "read")

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

        raise BadPivot("Doesn't match poprsp")

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
            raise BadPivot("Register isn't a allowlisted Pivot register")

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
            raise BadPivot("Push poprsp should end in ret")
        if middle_insts.count("pop rsp") != 1:
            raise BadPivot("Should have exactly one pop rsp")

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
            raise BadPivot("Indirect register not allowlisted")

        if offset < -0x80 or offset >= 0x200:
            # These offsets are arbitrary
            raise BadPivot("Indirect gadget has large offset")

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

        return PushIndirectPivot(address, gadget, indirect_type, pivot_reg, list(memory_writes[pivot_reg]),
                                 jump_reg, jump_used_offsets, offset)

    def _check_if_pivot(self, address, gadget):
        """
        Checks if the gadget matches one of our pivot patterns.

        xchg reg|rsp, rsp|reg; ret
        mov rsp, reg; ret
        leave; ret
        push reg; … ; pop rsp; [pops]; ret
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
                raise BadPivot("Register being pushed not good register for pivot")

            # check if push ... pop rsp ... ret
            if gadget.count("pop rsp") == 1:
                return self._try_match_push_poprsp_pivot(address, gadget, pivot_reg)

            # check if push ... jump|call [reg]
            if last_inst.startswith("jmp") or last_inst.startswith("call"):
                return self._try_match_indirect_pivot(address, gadget, pivot_reg)

        # check if [popN, poprsp, popN ret]
        if re.match(POP_PATTERN, first_inst):
            return self._try_match_poprsp_pivot(address, gadget)

        raise BadPivot("No match")


def main():
    parser = argparse.ArgumentParser(description="ROP stack pivot finder")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="ERROR",
                        help="Set the logging level.")
    parser.add_argument("--backend", choices=["rp++", "text"], default="rp++",
                        help="Backend to use for processing: "
                             "'rp++': use the rp++ tool (default), "
                             "'text': use a text file produced by either the "
                             "rp++ or the ROPgadget tools.")
    parser.add_argument("--vmlinux", help="Path to the vmlinux file, filters gadgets"
                        "only within the .text section if the 'text' backend is used")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--text-output-format", choices=["original", "short"], default="original")
    parser.add_argument("--json-indent", type=int, default=None)
    parser.add_argument("input_file", help="Path to the input file (vmlinux binary for "
                        "the 'rp++' backend, text file containing ROP gadgets for the "
                        "'text' gadget)")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level))

    if args.backend == "text":
        backend = gadget_finder.TextFileBackend(args.input_file, args.vmlinux)
    else:
        backend = gadget_finder.RppBackend(args.input_file, CONTEXT_SIZE)

    pivot_finder = PivotFinder(backend)
    pivots = pivot_finder.find_pivots()

    if args.output == "json":
        print(PivotSerializer.serialize(pivots, indent=args.json_indent))
    else:
        combined_pivots = pivots.combined_list()
        sys.stderr.write(f"Found {len(combined_pivots)} pivots.\n")
        for pivot in combined_pivots:
            if args.text_output_format == "short":
                pivot_desc = ", ".join([f"{repr(value)}" for (key,value) in pivot.__dict__.items() if key not in ["address", "instructions"]])
                print(f"{'; '.join(pivot.instructions):<50}// {pivot.__class__.__name__}({pivot_desc})")
            else:
                pivot.debug_print()
                print()

if __name__ == "__main__":
    main()
