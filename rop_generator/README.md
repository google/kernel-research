# Kernel ROP Generator

## Description
Tools for generating ROP chains on Linux Kernel images.

```angrop_rop_generator.py``` works by patching the binary (using rop_instruction_patcher.py) to replace the various thunks and runtime patches. These thunks are replaced with nops or invalid instructions to avoid them being identified as possible gadgets.
Calls to ```__x86_return_thunk``` are replaced with ```ret``` so that angrop/rp++ can find gadgets correctly

## Usage
1. Generate ROP chain with angrop_rop_generator.py
    * ```python angrop_rop_generator.py <vmlinux path> <vmlinuz path>```
    * ```<vmlinux image>``` needs to include symbols
    * outputs the generated ROP chain

## Testing
To test the generated ROP chain, we patch the following syscalls
* Patch ```__sys_shutdown ``` to copy ROP chain from user to kernel memory
* Patch ```__x64_sys_reboot``` to jump to the ROP chain
* Run ```python kernel_syscall_patcher.py  <vmlinux path>```
* This outputs ```<vmlinux>.syscall_patched```

Copy the generated ROP chain into rop_test_trigger.c
* Compile ```gcc -static -o rop_test_trigger rop_test_trigger.c```
* ``` cp rop_test_trigger <image_runner path>/rootfs/```
* Run the patched vmlinux in QEMU ```./run_vmlinuz.sh <vmlinux>.syscall_patched sh```
* Inside QEMU run ```./rop_test_trigger```

