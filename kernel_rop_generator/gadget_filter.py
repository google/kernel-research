import re
import archinfo


class GadgetFilter:
    """Filters ROP gadgets"""

    def __init__(self) -> None:
        """Initializes the ROP generator.

        Args:
          vmlinux_path: path to the vmlinux file
        """
        self.partial_regs = self._get_partial_regs()

    def filter_gadgets(self, gadgets):
        """
        Filters gadgets to identify potentially useful ROP gadgets.

        Args:
          gadgets: A dict of gadgets.

        Returns:
          A dict of filtered gadgets
        """
        filtered = dict()
        for addr, gadget in gadgets.items():
            if self._possible_rop_gadget(gadget):
                filtered[addr] = gadget
        return filtered

    def _get_partial_regs(self):
        """
        Identifies a set of register names that represent partial registers
        within the AMD64 architecture. Partial registers refer to
        smaller portions of larger registers (e.g., 'al' is the lower 8 bits of 'rax').

        Returns:
            A set containing the names of partial registers in the AMD64 architecture.
        """
        partial_regs = set()

        # for each register find the base register name and store in a dictionary
        arch = archinfo.ArchAMD64()
        for reg, (offset, _) in arch.registers.items():
            base_reg_off_size = arch.get_base_register(offset)
            base_reg_name = arch.register_size_names[base_reg_off_size]
            if base_reg_name != reg:
                partial_regs.add(reg)

        return partial_regs

    def _get_alphanumeric_strings(self, instruction):
        """
        Extracts all alphanumeric strings from an assembly instruction.

        Args:
            instruction (str): The assembly instruction string.

        Returns:
            list: A list of alphanumeric strings found in the instruction.
        """
        pattern = r"\b[a-zA-Z0-9]+\b"  # Matches one or more alphanumeric characters
        matches = re.findall(pattern, instruction)
        return matches

    def _has_multiple_registers_in_memory_address(self, instruction):
        """
        Checks if an assembly instruction has multiple registers within a memory address.

        This function analyzes an assembly instruction to determine if it contains
        a memory address with two or more registers. This is often used to identify
        complex addressing modes that might be less desirable for ROP gadgets.

        Args:
            instruction: The assembly instruction string to analyze.

        Returns:
            True if the instruction has a memory address with two or more registers,
            False otherwise.
        """
        # Define a pattern to match an address part: e.g., [reg1+reg2], [reg1+reg2*scale], etc.
        # This will capture the part inside square brackets []
        address_pattern = r"\[([^\]]+)\]"

        match = re.search(address_pattern, instruction)

        if match:
            # The address part is the string inside the square brackets
            address = match.group(1).strip()

            # Find all words that start with a letter and may be followed by alphanumeric characters
            # This matches any word starting with a letter, followed by any number of alphanumeric characters or underscores
            registers = re.findall(r"\b[a-zA-Z]\w*\b", address)

            # Check if there are exactly two registers in the address
            return len(registers) >= 2

        return False

    def _has_multiplication_in_memory_address(self, assembly_code):
        """
        Checks if the given assembly code has multiplication inside a memory address.

        Args:
        assembly_code: The assembly code to check.

        Returns:
        True if multiplication is found inside a memory address, False otherwise.
        """
        pattern = r"\[.*?\*.*?\]"  # Matches any multiplication within square brackets
        return bool(re.search(pattern, assembly_code))

    def _possible_rop_gadget(self, gadget):
        """
        Check if a given gadget is a potentially useful ROP gadget.
        In the linux kernel, there are a large number of ROP gadgets. We can use heuristics
        to filter out more comlicated gadgets and still have plenty of gadgets to work with.
        We do mostly for speed, otherwise angrop is slower.

        This function applies a series of heuristic checks to determine if a given
        gadget is likely to be useful for ROP exploitation. It filters out gadgets
        that are unlikely to be helpful based on various criteria, such as:

        * Instructions that clobber the stack pointer (rsp)
        * Gadgets that start with useless or undesirable instructions
        * Gadgets with complex memory addressing modes
        * Gadgets that change the interrupt state or use segment registers
        * Gadgets with input/output operations or locking instructions
        * Gadgets with too many memory reads/writes
        * Gadgets with large return offsets
        * Gadgets with division instructions or floating-point operations

        Args:
            gadget: A list of strings representing the assembly instructions in the gadget.

        Returns:
            True if the gadget passes all the checks and is considered potentially useful,
            False otherwise.
        """
        if not gadget[-1].startswith("ret"):
            return False
        gadget_str = "; ".join(gadget)

        # patterns that will clobber rsp
        clobber_patterns = ["esp,", "leave", "pop rsp",
                            "mov rsp", "xor rsp", "enter", "lea rsp"]
        for pattern in clobber_patterns:
            if pattern in gadget_str:
                return False

        # check for xchg with esp or rsp
        pattern = r"xchg\s+(?:[a-z]{3}|r[a-z]{2}),\s+(?:esp|rsp)"
        match = re.search(pattern, gadget_str, re.IGNORECASE)
        if match:
            return False

        # we don't care about gadgets that start with useless instructions
        useless_first_insts = ["shr", "sar", "sal", "shl", "ror", "rol", "rcr", "rcl",
                               "or", "xor", "not", "neg", "and", "bsr", "bsf", "bswap",
                               "bt", "btr", "bts", "cdq", "cwd", "cbw",  # bit operations
                               "nop",  # no-ops
                               "aa", "ad", "sub", "sb", "mul", "imul", "inc", "dec",  # math
                               "test", "cmp", "xlatb", "stc", "set", "salc", "clc", "cmc", "sahf", "lahf",  # flags
                               "stos", "rep", "scas",
                               "push", "popfq",
                               "movs",  # some sign extend or floating moves start with movs
                               ]
        for inst in useless_first_insts:
            if gadget[0].startswith(inst):
                return False

        # if the first inst is a memory one it should be a qword not byte word dword
        if "[" in gadget[0]:
            if " byte " in gadget[0] or " word " in gadget[0] or " dword " in gadget[0]:
                return False

        # if the first inst is a memory one it should be a mov or lea instruction
        if "[" in gadget[0]:
            if not gadget[0].startswith("mov") and not gadget[0].startswith("lea"):
                return False

        # first instruction should use full registers, not half registers
        for s in self._get_alphanumeric_strings(gadget[0]):
            if s in self.partial_regs:
                return False

        # first instruction should not use a constant as an operand or a memory address
        first_operands = gadget[0].split(" ", 1)[-1].split(",")
        stripped_operands = [x.strip() for x in first_operands]
        for operand in stripped_operands:
            if operand[0].isdigit():
                return False
            if '[' in operand:
                bracket_idx = operand.index('[')
                if operand[bracket_idx+1].isdigit():
                    return False

        # if the first instruction is a memory read or write we can filter ones with offsets
        # there's so many gadgets we don't need complex ones here
        if gadget[0].startswith("mov") and '[' in gadget[0]:
            # Matches + or - within square brackets
            pattern = r"\[.*?[\+\-].*?\]"
            if re.search(pattern, gadget[0]):
                return False

            # can also filter longer ones out
            if len(gadget) > 3:
                return False

        # there's tons of pop rbp and pop rbx so limit those as well
        if gadget[0] == "pop rbp" or gadget[0] == "pop rbx":
            if len(gadget) > 3:
                return False

        # multiple registers in any memory address
        if self._has_multiple_registers_in_memory_address(gadget_str):
            return False
        # multiplication in memory address
        if self._has_multiplication_in_memory_address(gadget_str):
            return False

        # instructions that change interrupt state
        bad_insts = ["int3", "sys", "vmm", "undefined", "hlt", "ud2", "trap", "cli",
                     "sti", "lgdt", "lidt", "sgdt", "sidt", "wait", "std", "cld"]
        for inst in bad_insts:
            if inst in gadget_str:
                return False

        # anything that uses segment registers
        bad_regs = ["cs", "ds", "es", "fs", "gs", ":", "seg"]
        # Use regex to avoid matching partial words
        escaped_regs = [re.escape(reg) for reg in bad_regs]
        pattern = r"\b(" + "|".join(escaped_regs) + r")\b"

        if re.search(pattern, gadget_str):
            return False

        # input and output
        if "in" in gadget_str or "out" in gadget_str:
            return False

        # locking instructions
        lock_insts = ["lock", "xadd", "cmpxchg", "fence", "pause"]
        for inst in lock_insts:
            if inst in gadget_str:
                return False

        # too many memory writes/reads
        if gadget_str.count("[") > 1:
            return False

        # large retn
        # Matches "retn" followed by a hex value
        pattern = r"\bretn\s+0x([0-9a-fA-F]+)\b"
        match = re.search(pattern, gadget[-1], re.IGNORECASE)
        if match:
            offset_str = match.group(1)
            if abs(int(offset_str, 16)) > 0x100:
                return False

        # div instructions
        if "div" in gadget_str:
            return False

        # floating point
        floating_patterns = ["xmm", "ymm", "st0"]
        for pattern in floating_patterns:
            if pattern in gadget_str:
                return False

        # lots of pop gadgets we don't need complicated ones
        if gadget[0].startswith("pop"):
            # if it starts with a pop, there shouldn't be any memory reads/writes
            if '[' in gadget_str:
                return False
            if "push" in gadget_str:
                return False

        return True
