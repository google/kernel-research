## The Problem: Unreliable Gadgets from Runtime Patching

ROP gadget finders work by statically analyzing a binary for useful instruction sequences. A significant challenge with the Linux kernel is that its binary (`vmlinux`) is not entirely static. Numerous instruction sequences are intentionally modified or relocated at boot time or runtime.

This dynamic modification poses a problem: **a ROP finder might identify gadgets within an instruction that will be altered or replaced when the kernel is actually running.** These "phantom" gadgets are unusable in a real exploit chain because the underlying bytes at that memory address will have changed.

Our goal is to prevent the ROP finder from using these unstable regions of code.

---

## The Solution: Pre-emptive Patching

To ensure the gadgets found are reliable, we pre-process the `vmlinux` binary before running the ROP finder. The `rop_instruction_patcher.py` script identifies all code locations that are subject to runtime modification and patches them by overwriting them with benign instructions like `0xcc` or `NOP`s.

This patching hides the unstable instruction sequences from the ROP finder, ensuring that any discovered gadgets will exist in a running kernel. The script takes a `vmlinux` and `vmlinuz` file as input and generates a new, patched `vmlinux` file ready for gadget analysis.

---

## Types of Patched Instructions

The script identifies and patches the following runtime-modified code.

### 1. Alternative Instructions (`.altinstructions`)
* **What it is:** A mechanism for runtime CPU feature detection. The kernel contains default instruction sequences that can be replaced by more optimized versions if a specific CPU feature (e.g., a new instruction set) is present. This is managed in the `.altinstructions` section.
* **Patch:** The script overwrites the original, default instruction with `NOP`s to prevent gadgets from being found in code that may be replaced.

### 2. Static Calls (`.static_call_sites`)
* **What it is:** A performance optimization that can turn an indirect call into a direct `call` or `jmp` at runtime if the target function is known. These sites are initially placeholders.
* **Patch:** The script overwrites the 4-byte relative offset of the `call`/`jmp` instruction with `0xcccccccc`, invalidating the instruction.

### 3. Function Entry Tracing (`__fentry__`)
* **What it is:** At the beginning of many kernel functions, a `call __fentry__` instruction is placed to enable tracing and profiling tools like `ftrace`. At runtime, these calls are often patched into `NOP`s if tracing is disabled.
* **Patch:** The script replaces the 5-byte `call` instruction with a 5-byte `NOP` (`0x0f1f440000`).

### 4. Return Thunks (`__x86_return_thunk`)
* **What it is:** Part of the kernel's mitigations against Spectre v2 attacks. Some `ret` instructions are replaced with `jmp __x86_return_thunk`.
* **Patch:** The script replaces the 5-byte `jmp` instruction with `ret; int3; int3; int3; int3;` (`0xc3cccccc`). This has the added benefit of enabling rop gadget finders to see the ret and detect it as a possible rop gadget. 

### 5. Indirect Branch Thunks (`__x86_indirect_thunk_*`)
* **What it is:** Another mitigation against Spectre v2 (Retpolines). Indirect calls and jumps (`call *rax`, `jmp *rbx`) are replaced with calls to a special thunk function (e.g., `call __x86_indirect_thunk_rax`). At runtime, this thunk is patched to perform a safe indirect branch.
* **Patch:** The script assembles the correct `call <reg>` or `jmp <reg>` instruction (which is shorter than the original 5-byte relative call) and pads the remaining bytes with `0xcc`. For example, a `call __x86_indirect_thunk_rax` is replaced with `call rax; int3; int3; int3;`.

### 6. General Load-Time Relocations
* **What it is:** Many instructions contain absolute addresses or offsets that are only known once the kernel is loaded into memory (especially with KASLR). For example, `mov rdx, gs:current_vmcs` contains an offset to `current_vmcs` that is fixed up at boot.
* **Patch:** The script overwrites the 4-byte immediate value or offset within these instructions with `0xcccccccc`.

---

## Identification Methods

The script uses a two-pronged approach to find these locations, mirroring the evolution of the Linux kernel's build process.

### Method 1: Using ELF Relocation Sections

For kernel versions that are built with relocation information (`.rela.text`), the script parses these sections directly. The script looks for relocations pointing to symbols like:
* `__fentry__`
* `__x86_return_thunk`
* `__x86_indirect_thunk_*`

It also identifies general load-time relocations described above.

### Method 2: Using Kernel-Specific Tables

Modern kernels are often built without ELF relocation sections in the final `vmlinux` file. In this case, the script parses the same data structures the kernel itself uses at boot time to perform these patches.

The logic for parsing these tables is inspired by their implementation in the kernel source code:

* **Retpoline Sites (`.retpoline_sites`):** Finds indirect branch thunks.
    * *Inspired by:* `apply_retpolines()` in `arch/x86/kernel/alternative.c`.
* **Return Sites (`.return_sites`):** Finds `jmp __x86_return_thunk` sites.
    * *Inspired by:* `apply_returns()` in `arch/x86/kernel/alternative.c`.
* **Fentry Call Table (`__start_mcount_loc`):** Finds `call __fentry__` sites by parsing a table of their addresses.
    * *Inspired by:* `callthunks_patch_builtin_calls()` in `arch/x86/kernel/callthunks.c`.
* **`vmlinuz` Relocations:** For KASLR-aware relocations, the offsets are not in `vmlinux`. The script extracts the compressed kernel from `vmlinuz` and reads the relocation tables appended at the end of the file.
    * *Inspired by:* `handle_relocations()` in `arch/x86/boot/compressed/misc.c`.

---

## Usage

To use the patcher, run the script with the paths to your `vmlinux` and `vmlinuz` files.

```bash
python3 rop_instruction_patcher.py /path/to/vmlinux /path/to/vmlinuz