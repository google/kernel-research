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

import argparse
from collections import defaultdict
import logging
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from keystone import *

from rop_util import get_offset, setup_logger, load_symbols, get_segment_by_addr

RETURN_THUNK_BYTES_REPLACE = b"\xc3\xcc\xcc\xcc\xcc"
FENTRY_BYTES_REPLACE = b"\x0f\x1f\x44\x00\x00"
RUNTIME_RELOCATED_BYTES_REPLACE = b"\xcc\xcc\xcc\xcc"
STATIC_CALL_REPLACE = b"\xcc\xcc\xcc\xcc"
OUTPUT_FILE_EXTENTION = ".thunk_replaced"

logger = setup_logger("rop_instruction_patcher")

"""
This file patches various instructions which will be patched by the kernel at load-time.
By doing this we can avoid finding incorrect rop gadgets which won't be there in a running kernel.

There are 4 types we handle.
Calls to __fentry__:
    These are nopped out
Jumps to __x86_return_thunk:
    These are replaced with a ret + 0xcc
Jumps/Calls to __x86_indirect_thunk_*:
    These are replaced with jmp/call reg + 0xcc
gs:0x20c80:
    In kernels with relocations, these values seem to be sometimes changed at load time.
    These are replaced with 0xcc
"""


class RopInstructionPatcher:
    def __init__(self, vmlinux_path) -> None:
        self.vmlinux_path = vmlinux_path
        self.alternatives = []
        self.static_call_sites = []
        self.fentry_calls = []
        self.return_thunks = []
        self.indirect_thunk_calls = defaultdict(list)
        self.indirect_thunk_jumps = defaultdict(list)
        self.other_relocations = []
        self._symbols = None
        self._indirect_thunk_symbols = dict()
        self.get_indirect_thunk_symbols()
        self.find_relocated_instructions()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def get_indirect_thunk_symbols(self):
        self._symbols = load_symbols(self.vmlinux_path)
        for sym, addr in self._symbols.items():
            if sym.startswith("__x86_indirect_thunk_"):
                reg = sym.replace("__x86_indirect_thunk_", "")
                if len(reg) < 4:
                    self._indirect_thunk_symbols[addr] = reg


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
                ins_byte = linked_section_bytes[call_start - linked_section_start]
                if (ins_byte == 0xe8):
                    self.fentry_calls.append(call_start)
            elif "__x86_return_thunk" == symbol_name:
                return_start = relocation.entry['r_offset']-1
                ins_byte = linked_section_bytes[return_start - linked_section_start]
                if (ins_byte == 0xe9):
                    self.return_thunks.append(return_start)
            elif "__x86_indirect_thunk_" in symbol_name:
                reg_name = symbol_name.replace("__x86_indirect_thunk_", "")
                if len(reg_name) <= 3:  # ensure it's a register
                    thunk_start = relocation.entry['r_offset']-1
                    ins_byte = linked_section_bytes[thunk_start - linked_section_start]
                    if ins_byte == 0xe8:
                        self.indirect_thunk_calls[reg_name].append(thunk_start)
                    if ins_byte == 0xe9:
                        self.indirect_thunk_jumps[reg_name].append(thunk_start)

            # now check for other relocations which change bytes
            # Low 32 bits on x64
            r_info_type = relocation.entry['r_info'] & 0xFFFFFFFF

            # if type is 2 and symbol_value is small then it is a relocation which will change bytes
            # these correspond to instructions like "mov rdx, gs:current_vmcs"
            if r_info_type == 2 and (symbol_value is None or symbol_value < 2**32):
                offset = relocation.entry['r_offset']
                self.other_relocations.append(offset)

    def get_alt_instr_struct(self, altinstr_data):
        """
        Hueristically determine the struct layout of the alt_instr struct
        Could get this from the parsed structs.json
        However, that would limit applicability of this tool as a standalone

        We need the following fields
          s32 instr_offset;	/* original instruction */
	      s32 repl_offset;	/* offset to replacement instruction */
          ...
	      u8  instrlen;		/* length of original instruction */
	      u8  replacementlen;	/* length of new instruction */
        """

        # struct size must be at least 10, likely to be under 0x20
        # instr_offset is always at the beginning
        # instrlen and replacementlen are near the end
        # guess size and instrlen offset

        # find a guess where the lengths of instrlen, replacementlen all make sense
        for size in range(10, 0x20):
            if len(altinstr_data) % size != 0:
                continue

            # iterate reversed as instrlen is near the end, flags are before it
            for instrlen_offset in reversed(range(8, size-1)):
                match = True
                has_nonzero_repl = False
                for test_offset in range(0, len(altinstr_data), size):
                    instrlen = altinstr_data[test_offset+instrlen_offset]
                    replacementlen = altinstr_data[test_offset+instrlen_offset+1]
                    # check that instrlen >= replacementlen
                    if instrlen < replacementlen:
                        match = False
                        break
                    if replacementlen > 0:
                        has_nonzero_repl = True
                # we should have seen some non-zero replacements
                if match and has_nonzero_repl:
                    logger.debug("got alt_instr size and instrlen_offset %d %d", size, instrlen_offset)
                    return size, instrlen_offset

        raise RuntimeError("Could not determine alt_instr struct layout")

    def process_alternatives(self, elffile):
        """
        For alternatives see apply_alternatives() in arch/x86/kernel/alternative.c
        """
        altinstr_section = elffile.get_section_by_name('.altinstructions')

        if altinstr_section is None:
            logger.warning("'.altinstructions' section not found.")
            return

        data = altinstr_section.data()  # Get the raw bytes of the section
        data_size = len(data)
        base = altinstr_section['sh_addr']

        text_section = elffile.get_section_by_name('.text')
        text_section_base = text_section['sh_addr']
        text_section_data = text_section.data()
        text_section_end = text_section_base+len(text_section_data)

        # first determine size of the struct `alt_instr` and offset of instrlen
        struct_size, instrlen_off = self.get_alt_instr_struct(data)

        # Iterate through the data
        offset = 0
        for offset in range(0, data_size, struct_size):
            address = base + offset + struct.unpack_from("<i", data, offset)[0]
            if address >= text_section_end:
                continue

            length = data[offset+instrlen_off]
            self.alternatives.append((address, length))

    def get_buf_from_elf(self, elffile, start, end):
        size = end-start

        for segment in elffile.iter_segments():
            if segment['p_type'] == 'PT_LOAD':  # Look for loadable segments
                seg_start_va = segment['p_vaddr']
                seg_end_va = seg_start_va + segment['p_memsz']
                if seg_start_va <= start < seg_end_va:  # Check if VA is within segment range
                    offset_in_segment = start - seg_start_va
                    return segment.data()[offset_in_segment:offset_in_segment+size]
        raise RuntimeError("Couldn't find segment with address")

    def process_static_call_sites(self, elffile):
        """
        For static call sites see in kernel/static_call_inline.c

        struct static_call_site {
            s32 addr;
            s32 key;
        };
        """
        start = self._symbols["__start_static_call_sites"]
        end = self._symbols["__stop_static_call_sites"]

        data = self.get_buf_from_elf(elffile, start, end)
        data_size = len(data)
        base = start

        text_section = elffile.get_section_by_name('.text')
        text_section_base = text_section['sh_addr']
        text_section_data = text_section.data()
        text_section_end = text_section_base+len(text_section_data)

        # Iterate through the data

        for offset in range(0, data_size, 8):
            address = base + offset + struct.unpack_from("<i", data, offset)[0]
            if address >= text_section_end:
                continue

            instr = text_section_data[address-text_section_base:address-text_section_base+5]
            assert instr[0] == 0xe8 or instr[0] == 0xe9

            self.static_call_sites.append(address)

    def process_retpoline_sites_section(self, elffile):
        """
        For retpolines see apply_retpolines() in arch/x86/kernel/alternative.c
        """
        retpoline_section = elffile.get_section_by_name('.retpoline_sites')

        if retpoline_section is None:
            logger.warning("'.retpoline_sites' section not found.")
            return

        data = retpoline_section.data()  # Get the raw bytes of the section
        data_size = len(data)
        base = retpoline_section['sh_addr']

        text_section = elffile.get_section_by_name('.text')
        text_section_base = text_section['sh_addr']
        text_section_data = text_section.data()
        text_section_end = text_section_base+len(text_section_data)

        # Iterate through the data
        offset = 0
        for offset in range(0, data_size, 4):
            address = base + offset + struct.unpack_from("<i", data, offset)[0]
            if address >= text_section_end:
                continue
            instr = text_section_data[address-text_section_base:address-text_section_base+5]
            if instr[0] == 0x2e:
                # skip one byte (we keep the 2e?)
                address += 1
                instr = text_section_data[address-text_section_base:address-text_section_base+5]
            target = address+5+struct.unpack_from("<i", instr, 1)[0]
            reg = self._indirect_thunk_symbols[target]
            if instr[0] == 0xe8:
                self.indirect_thunk_calls[reg].append(address)
            elif instr[0] == 0xe9:
                self.indirect_thunk_jumps[reg].append(address)
            else:
                assert False, "expected jmp or call"

    def process_return_sites_section(self, elffile):
        """
        For returns see apply_returns() in arch/x86/kernel/alternative.c
        """
        return_section = elffile.get_section_by_name('.return_sites')

        if return_section is None:
            logger.warning("'.return_sites' section not found.")
            return

        data = return_section.data()  # Get the raw bytes of the section
        data_size = len(data)
        base = return_section['sh_addr']

        text_section = elffile.get_section_by_name('.text')
        text_section_end = text_section['sh_addr']+len(text_section.data())

        # Iterate through the data
        offset = 0
        for offset in range(0, data_size, 4):
            address = base + offset + struct.unpack_from("<i", data, offset)[0]
            if address >= text_section_end:
                continue
            self.return_thunks.append(address)

    def process_fentry_table(self, elffile):
        """
        For fentry patches see callthunks_patch_builtin_calls() in arch/x86/kernel/callthunks.c
        """
        if "__start_mcount_loc" not in self._symbols:
            logger.warning("no __start_mcount_loc, cannot process fentry calls")
            return

        start_addr = self._symbols["__start_mcount_loc"]
        end_addr = self._symbols["__stop_mcount_loc"]

        text_section = elffile.get_section_by_name('.text')
        text_section_end = text_section['sh_addr']+len(text_section.data())

        # get segment containing addr
        segment = get_segment_by_addr(elffile, start_addr)
        seg_start_va = segment['p_vaddr']
        data = segment.data()[start_addr-seg_start_va:end_addr-seg_start_va]
        data_size = len(data)

        # Iterate through the data
        offset = 0
        for offset in range(0, data_size, 8):
            address = struct.unpack_from("<Q", data, offset)[0]
            if address >= text_section_end:
                continue
            self.fentry_calls.append(address)

    def find_relocated_instructions(self):
        """
        Finds relocated instructions in a kernel image using pyelftools.
        """
        with open(self.vmlinux_path, 'rb') as f:
            elffile = ELFFile(f)

            # always process alternatives
            self.process_alternatives(elffile)
            self.process_static_call_sites(elffile)

            # Check for relocations and process relocation sections referring to .text
            has_relocs = False
            for section in elffile.iter_sections():
                if isinstance(section, RelocationSection):
                    linked_section = elffile.get_section(section['sh_info'])
                    linked_section_name = linked_section.name

                    # only process .text, as it is the only section the rop code will use
                    if linked_section_name == ".text":
                        self.process_relocation_section(elffile, section)
                        has_relocs = True

            if not has_relocs:
                logger.debug("no relocations... using tables")
                # in some versions there is no relocation section
                # we can instead process these from other sections and symbols
                self.process_retpoline_sites_section(elffile)
                self.process_return_sites_section(elffile)
                self.process_fentry_table(elffile)


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

            for addr, length in self.alternatives:
                self.replace_bytes(vmlinux_bytes, elffile, addr, b"\x90"*length)

            for addr in self.static_call_sites:
                # replace the call/jump target with cc so no mid-instruction gadgets
                self.replace_bytes(vmlinux_bytes, elffile, addr+1, STATIC_CALL_REPLACE)

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

            for addr in self.other_relocations:
                self.replace_bytes(vmlinux_bytes, elffile,
                                   addr, RUNTIME_RELOCATED_BYTES_REPLACE)

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
