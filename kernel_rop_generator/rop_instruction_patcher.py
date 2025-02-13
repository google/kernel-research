import argparse
import logging
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from keystone import *
from rop_util import get_offset, setup_logger
from collections import defaultdict

RETURN_THUNK_BYTES_REPLACE = b"\xc3\xcc\xcc\xcc\xcc"
FENTRY_BYTES_REPLACE = b"\x0f\x1f\x44\x00\x00"
RUNTIME_RELOCATED_BYTES_REPLACE = b"\xcc\xcc\xcc\xcc"
OUTPUT_FILE_EXTENTION = ".thunk_replaced"

logger = setup_logger("rop_instruction_patcher")

class RopInstructionPatcher:
    def __init__(self, vmlinux_path) -> None:
        self.vmlinux_path = vmlinux_path
        self.fentry_calls = []
        self.return_thunks = []
        self.indirect_thunk_calls = defaultdict(list)
        self.indirect_thunk_jumps = defaultdict(list)
        self.other_relocations = []
        self.find_relocated_instructions()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def process_relocation_section(self, elffile, reloc_section):
        """
        Processes a relocation section to find relocated  and patched instructions.
        Currently we look for and replace calls to __fentry__, __x86_return_thunk, __x86_indirect_thunk_*
        And relocations like "mov rdx, gs:current_vmcs" which are changed at load time
        """
        symbol_table = elffile.get_section(reloc_section['sh_link'])
        assert isinstance(symbol_table, SymbolTableSection)

        linked_section = elffile.get_section(reloc_section['sh_info'])
        linked_section_bytes = linked_section.data()
        linked_section_start = linked_section['sh_addr']

        for relocation in reloc_section.iter_relocations():
            symbol = symbol_table.get_symbol(relocation.entry['r_info_sym'])
            symbol_value = symbol['st_value'] if symbol['st_value'] != 0 else None
            symbol_name = symbol.name if symbol.name else "Unnamed Symbol"

            # check for __fentry__, __x86_return_thunk, x86_indirect_thunk_REG which are replaced at runtime
            if "__fentry__" == symbol_name:
                call_start = relocation.entry['r_offset']-1
                ins_byte = linked_section_bytes[call_start -
                    linked_section_start]
                if (ins_byte == 0xe8):
                    self.fentry_calls.append(call_start)
            if "__x86_return_thunk" == symbol_name:
                return_start = relocation.entry['r_offset']-1
                ins_byte = linked_section_bytes[return_start -
                    linked_section_start]
                if (ins_byte == 0xe9):
                    self.return_thunks.append(return_start)
            if "__x86_indirect_thunk_" in symbol_name:
                reg_name = symbol_name.replace("__x86_indirect_thunk_", "")
                if len(reg_name) <= 3:  # ensure it's a register
                    thunk_start = relocation.entry['r_offset']-1
                    ins_byte = linked_section_bytes[thunk_start -
                        linked_section_start]
                    if ins_byte == 0xe8:
                        self.indirect_thunk_calls[reg_name].append(thunk_start)
                    if ins_byte == 0xe9:
                        self.indirect_thunk_jumps[reg_name].append(thunk_start)

            # now check for other relocations which change bytes
            # Low 32 bits on x64
            r_info_type = relocation.entry['r_info'] & 0xFFFFFFFF

            # if type is 2 and symbol_value is small then it is a relocation which will change bytes
            # these correspond to instructions like "mov rdx, gs:current_vmcs"
            if r_info_type == 2 and (symbol_value is None or symbol_value < 0x1000000000):
                offset = relocation.entry['r_offset']
                self.other_relocations.append(offset)


    def find_relocated_instructions(self):
        """
        Finds relocated instructions in a kernel image using pyelftools.
        """
        with open(self.vmlinux_path, 'rb') as f:
            elffile = ELFFile(f)

            # Check for relocations
            has_relocs = False
            for section in elffile.iter_sections():
                if isinstance(section, RelocationSection):
                    has_relocs = True
                    break

            assert has_relocs

            # iterate sections and process relocation sections referring to .text
            for section in elffile.iter_sections():
                if isinstance(section, RelocationSection):
                    linked_section = elffile.get_section(section['sh_info'])
                    linked_section_name = linked_section.name

                    # only process .text, as it is the only section the rop code will use
                    if linked_section_name == ".text":
                        self.process_relocation_section(elffile, section)


    @staticmethod
    def replace_bytes(vmlinux_bytes, elffile, addr, replacement):
        """
        Replaces bytes in the vmlinux file which correspond to the addr given
        """
        offset = get_offset(elffile, addr)
        vmlinux_bytes[offset: offset + len(replacement)] = replacement


    def apply_patches(self, output_path):
        """
        Applies patches for all of the load-time patched instructions
        """
        # Read the original data
        with open(self.vmlinux_path, "rb") as vmlinux_file:
            vmlinux_bytes = bytearray(vmlinux_file.read())

        with open(self.vmlinux_path, "rb") as vmlinux_file:
            elffile = ELFFile(vmlinux_file)

            for addr in self.fentry_calls:
                self.replace_bytes(vmlinux_bytes, elffile,
                                   addr, FENTRY_BYTES_REPLACE)

            for addr in self.return_thunks:
                self.replace_bytes(vmlinux_bytes, elffile,
                                   addr, RETURN_THUNK_BYTES_REPLACE)

            for reg in self.indirect_thunk_calls:
                code, _ = self.ks.asm("call " + reg)
                # pad up to 5 bytes
                while len(code) < 5:
                    code.append(0xcc)
                replacement = bytes(code)
                for addr in self.indirect_thunk_calls[reg]:
                    self.replace_bytes(
                        vmlinux_bytes, elffile, addr, replacement)

            for reg in self.indirect_thunk_jumps:
                code, _ = self.ks.asm("jmp " + reg)
                # pad up to 5 bytes
                while len(code) < 5:
                    code.append(0xcc)
                replacement = bytes(code)
                for addr in self.indirect_thunk_jumps[reg]:
                    self.replace_bytes(
                        vmlinux_bytes, elffile, addr, replacement)

        # Write the patched data to the new file
        with open(output_path, "wb") as output_file:
            output_file.write(vmlinux_bytes)

        logger.debug("Patched vmlinux saved as %s", output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Replaces \"Relocations and Load-time kernel patches\" with custom bytes for finding the right ROP gadgets")
    parser.add_argument("vmlinux", help="Path to vmlinux file")
    file_path = parser.parse_args().vmlinux
    output_file_path = Path(file_path).with_suffix(OUTPUT_FILE_EXTENTION)
    logging.basicConfig(level=logging.DEBUG)
    reloc_patcher = RopInstructionPatcher(file_path)
    reloc_patcher.apply_patches(output_file_path)
