import argparse
from dataclasses import dataclass
from pathlib import Path
from elftools.elf.elffile import ELFFile
from pwn import asm
from rop_util import load_symbols, get_offset

DATA_SYMBOL = "print_fmt_ext4_fc_stats"
SYSCALL_REBOOT_SYMBOL = "__x64_sys_reboot"
SYSCALL_SHUTDOWN_SYMBOL = "__sys_shutdown"
INTERRUPT_SYMBOL = "timerfd_tmrproc"
CORE_PATTERN_SYMBOL = "core_pattern"
VMALLOC_SYMBOL = "vmalloc"
COPY_FROM_USER_SYMBOL = "_copy_from_user"
OUTPUT_FILE_EXTENTION = ".syscall_patched"


@dataclass
class Patch:
    """Represents a binary patch.

    Attributes:
        patch_addr (int): The address in the binary where the patch is to be applied.
        patch_bytes (bytes): The bytes to replace the original data at the patch_addr.
    """

    patch_addr: int
    patch_bytes: bytes


def assemble_copy_rop_patch(symbols):
    """
    TODO: Remove this once we use the custom kernel modules for testing ROP chains

    Assemble machine code to copy a ROP chain from userland to the kernel. We save the address of the copied ROP chain into 
    somewhere in Kernel data which won't be used. We chose the last 8 bytes of core pattern for this.

    rop_chain_kernel_addr = vmalloc(0x1000);
      mov rdi, 0x1000
      call vamlloc
      push rax
    copy_from_user(rop_chain_kernel_addr, 0x10000, 0x1000);
      mov rdi, rax
      mov rsi, 0x10000
      mov rdx, 0x1000
      call copy_from_user
    *(long*)(core_pattern+120) = (unsigned long)rop_chain_kernel_addr;
      pop rax
      mov [core_pattern+120], rax
    return 0
      xor rax, rax
      ret
    """
    vmalloc_addr = symbols[VMALLOC_SYMBOL]
    copy_from_user_addr = symbols[COPY_FROM_USER_SYMBOL]
    core_pattern_addr = symbols[CORE_PATTERN_SYMBOL]
    syscall_shutdown_addr = symbols[SYSCALL_SHUTDOWN_SYMBOL]

    # assemble the instructions to copy the rop chain from userland into the kernel
    # rop_chain_kernel_addr = vmalloc(0x2000)+0x1000;   // need some extra space for calls
    asm_copy_rop = f"mov rdi, 0x2000; call {hex(vmalloc_addr)}; add rax, 0x1000; push rax;"
    # copy_from_user(rop_chain_kernel_addr, 0x10000, 0x1000);
    asm_copy_rop += f"mov rdi, rax; mov rsi, 0x10000; mov rdx, 0x1000; call {(copy_from_user_addr)};"
    # *(long*)(core_pattern+120) = (unsigned long)rop_chain_kernel_addr;
    # core_pattern + 120 is to get to the end of core_pattern
    asm_copy_rop += f"pop rax; mov [{hex(core_pattern_addr + 120)}], rax; xor rax, rax; ret;"
    copy_rop = asm(asm_copy_rop, vma=syscall_shutdown_addr, arch="x86_64")
    return copy_rop


def assemble_jump_rop_patch(symbols):
    """
    Assemble the instructions to jump to rop chain
    """
    core_pattern_addr = symbols[CORE_PATTERN_SYMBOL]
    jump_rop = asm(
        f"mov rsp, [{hex(core_pattern_addr + 120)}]; ret", arch="x86_64")
    return jump_rop


def write_patches(vmlinux_path, patches, output_path):

    with open(vmlinux_path, "rb") as f:
        vmlinux_bytes = f.read()

    with open(vmlinux_path, 'rb') as f:
        elffile = ELFFile(f)

        for patch in patches:
            file_offset = get_offset(elffile, patch.patch_addr)

            # patch the shutdown syscall to copy the rop chain from userland
            vmlinux_bytes = vmlinux_bytes[:file_offset] + \
                patch.patch_bytes + \
                vmlinux_bytes[file_offset + len(patch.patch_bytes):]

    with open(output_path, "wb") as f:
        f.write(vmlinux_bytes)


def main(vmlinux_path):
    symbols = load_symbols(vmlinux_path)
    syscall_shutdown_addr = symbols[SYSCALL_SHUTDOWN_SYMBOL]
    syscall_reboot_addr = symbols[SYSCALL_REBOOT_SYMBOL]
    interrupt_addr = symbols[INTERRUPT_SYMBOL]
    output_path = Path(vmlinux_path).with_suffix(OUTPUT_FILE_EXTENTION)

    patches = []

    copy_rop_bytes = assemble_copy_rop_patch(symbols)
    patches.append(Patch(syscall_shutdown_addr, copy_rop_bytes))

    jump_rop_bytes = assemble_jump_rop_patch(symbols)
    patches.append(Patch(syscall_reboot_addr, jump_rop_bytes))
    patches.append(Patch(interrupt_addr, jump_rop_bytes))

    write_patches(vmlinux_path, patches, output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("vmlinux_path", help="")
    args = parser.parse_args()

    main(args.vmlinux_path)
