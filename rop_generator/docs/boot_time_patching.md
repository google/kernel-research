# Bug reports

We run into the following boot time patching issues which caused invalid stack pivots.

## STATIC_CALL_TRAMP

Release: kernelCTF `cos-109-17800.372.84`

We select this stack pivot (one gadget, move RSP to RSI):

```
ffffffff812ab5fc <trace_find_cmdline+0x5c>:
ffffffff812ab5fc:       56                      push   rsi
ffffffff812ab5fd:       35 01 5b 5d 41          xor    eax,0x415d5b01
ffffffff812ab602:       5c                      pop    rsp
ffffffff812ab603:       e9 38 9a 35 01          jmp    ffffffff82605040 <__x86_return_thunk>
```

Which is a misalignedly interpreted code of this real code:

```
# in real code replaced with "0f 1f 44 00 00" (nop    DWORD PTR [rax+rax*1+0x0])
ffffffff812ab5fa:       e8 e9 56 35 01          call   ffffffff82600ce8 <__SCT__preempt_schedule>
ffffffff812ab5ff:       5b                      pop    rbx
ffffffff812ab600:       5d                      pop    rbp
ffffffff812ab601:       41 5c                   pop    r12
ffffffff812ab603:       e9 38 9a 35 01          jmp    ffffffff82605040 <__x86_return_thunk>
```

And the comment tells you the issue, *the `__SCT__preempt_schedule` call is replaced with nops*.

So what happens it breaks our stack pivot as it wants to jump to `e8 e9 [56] 35 01` so `56  push   rsi` but jumps to the replaced `0f 1f [44] 00 00 ...` and runs `44 00 00                add    BYTE PTR [rax],r8b` and rax is 1 (in this case) and we are getting `BUG: kernel NULL pointer dereference, address: 0000000000000001`.

SCT means "STATIC_CALL_TRAMP" and this code seems to generate it: https://github.com/torvalds/linux/blob/v6.6/arch/x86/include/asm/preempt.h#L128

This issue was solved in https://github.com/google/kernel-research/commit/e67b5c3909878479e9eae9c63ce1dcc0eff6af3a.

## Paravirt instructions

Release: kernelCTF `lts-6.6.69`

Stack pivot:
```
ffffffff8112f3a6 <vmware_cpu_online+0x16>:
ffffffff8112f3a6:       56                      push   rsi
ffffffff8112f3a7:       5c                      pop    rsp
ffffffff8112f3a8:       b2 02                   mov    dl,0x2
ffffffff8112f3aa:       31 c0                   xor    eax,eax
ffffffff8112f3ac:       e9 ef 23 35 01          jmp    ffffffff824817a0 <__x86_return_thunk>
```

Original code in the binary (the stack pivot is misaligned):
```
ffffffff8112f3a4:       ff 15 56 5c b2 02       call   QWORD PTR [rip+0x2b25c56]        # ffffffff83c55000 <pv_ops+0x100>
ffffffff8112f3aa:       31 c0                   xor    eax,eax
ffffffff8112f3ac:       e9 ef 23 35 01          jmp    ffffffff824817a0 <__x86_return_thunk>
```

Actual code running live:
```
28: fb                      sti
29: 0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
2e: 31 c0                   xor    eax,eax
30: e9 5a 4d 5d 01          jmp    0x15d4d8f
```

`pv_ops` doc is here: https://www.kernel.org/doc/Documentation/virt/paravirt_ops.rst, tl;dr:

> Linux pv_ops is a virtualization API which enables support for different hypervisors. It allows each hypervisor to override critical operations and allows a single kernel binary to run on all supported execution environments including native machine -- without any hypervisors.

> pv_ops provides a set of function pointers which represent operations corresponding to low level critical instructions and high level functionalities in various areas. pv-ops allows for optimizations at run time by enabling *binary patching of the low-ops critical operations at boot time*.

So tl;dr: if we are running in a VM then original compiled code runs, otherwise it is replaced with direct asm codes like `sti` (Set Interrupt Flag).

This is where it gets replaced: https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/alternative.c#L1609

This issue was solved in https://github.com/google/kernel-research/commit/e67b5c3909878479e9eae9c63ce1dcc0eff6af3a.
