import argparse
from pathlib import Path
import re
from elftools.elf.elffile import ELFFile
import angr
from rop_util import load_symbols, get_offset

RETURN_THUNK_BYTES_REPLACE = b"\xc3\xcc\xcc\xcc\xcc"
OUTPUT_FILE_EXTENTION = ".thunk_replaced"


def get_executable_ranges(project):
    """
    returns the ranges which are executable
    """
    # For kernel_mode we use .text if we can find it
    for section in project.loader.main_object.sections:
        if section.name == ".text":
            executable_ranges = [section]
            return executable_ranges


def get_jmp_addresses_by_byte_pattern(project):
    """
    Finds addresses within executable segments of a binary matching a byte pattern.

    Args:
        project: The angr project instance.

    Returns:
        list: A sorted list of addresses where the pattern is found.
    """
    # opcode for jump
    pattern = b"\xe9"

    addrs = []
    state = project.factory.entry_state()
    for segment in get_executable_ranges(project):
        # angr is slow to read huge chunks
        read_bytes = []
        for i in range(segment.min_addr, segment.min_addr+segment.memsize, 0x100):
            read_size = min(0x100, segment.min_addr+segment.memsize-i)
            read_bytes.append(state.solver.eval(
                state.memory.load(i, read_size), cast_to=bytes))
        read_bytes = b"".join(read_bytes)
        # find all occurrences of the e8_instructions
        # print("find all occurrences of the e9 (jmp) instructions")
        addrs += [segment.min_addr + m.start()
                  for m in re.finditer(pattern, read_bytes)]
    return sorted(addrs)


def replace_return_thunks(project, return_thunk_addr, vmlinux_bytes, elffile):
    """
    Checks all the addresses for jump to return_thunk_x86 and patches bytes there.
    """
    addresses = get_jmp_addresses_by_byte_pattern(project)
    for addr in addresses:
        ins = project.factory.block(addr).disassembly.insns[0]
        if ins.mnemonic == "jmp" and int(ins.op_str.rstrip('h'), 16) == return_thunk_addr:
            off_patch_addr = get_offset(elffile, addr)
            replace_return_thunk_bytes(vmlinux_bytes, off_patch_addr)


def replace_return_thunk_bytes(vmlinux_bytes, off_patch_addr):
    # read the file bytes and patch them

    vmlinux_bytes[off_patch_addr: off_patch_addr +
                  len(RETURN_THUNK_BYTES_REPLACE)] = RETURN_THUNK_BYTES_REPLACE


def patch_vmlinux_return_thunk(vmlinux_path, output_path):
    """
    Patches return thunks in the vmlinux kernel image.

    This function opens the vmlinux file, loads symbols, identifies return thunk addresses, 
    and replaces them with a custom patch. The patched binary is saved to a new file 
    with the ".thunk_replaced" extension.

    Args:
        vmlinux_path (str): The path to the vmlinux file.
    """

    project = angr.Project(vmlinux_path)
    symbols = load_symbols(vmlinux_path)
    return_thunk_addr = symbols["__x86_return_thunk"]

    # Read the original data
    with open(vmlinux_path, "rb") as vmlinux_file:
        vmlinux_bytes = bytearray(vmlinux_file.read())

    with open(vmlinux_path, "rb") as vmlinux_file:
        elffile = ELFFile(vmlinux_file)
        replace_return_thunks(project, return_thunk_addr,
                    vmlinux_bytes, elffile)

    # Write the patched data to the new file
    with open(output_path, "wb") as output_file:
        output_file.write(vmlinux_bytes)

    print(f"Patched vmlinux saved as '{output_path}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Patches \"jmp __x86_return_thunk\" with the custom bytes for finding the right ROP gadgets")
    parser.add_argument("vmlinux", help="Path to vmlinux file")
    file_path = parser.parse_args().vmlinux
    output_path = Path(file_path).with_suffix(OUTPUT_FILE_EXTENTION)
    patch_vmlinux_return_thunk(file_path, output_path)
