# xdk kernel module

The xdk kernel module helps simulating vulnerabilities in the kernel, tracking function calls and testing exploitation primitives.

# Usage

  1. Include the [xdk_device.h](./xdk_device.h) header file, so the structures used by the API will be available in the program.

  2. Open the `/dev/xdk` device for read and write:

  ```c
    int fd = open("/dev/xdk", O_RDWR);
  ```

  3. Send commands to the module via `ioctl`:

     ```c
     int ret;
     kpwn_message msg = { .length = 1024 };
     if ((ret = ioctl(fd, ALLOC_BUFFER, &msg)) != SUCCESS) {
         printf("kpwn command failed with %u\n", ret);
     }
     ```

     The return value of the `ioctl` is one of the `enum kpwn_errors` values:
        * zero is `SUCCESS`
        * non-zero values are errors


## Examples

Examples how to use the module can be found in the [test/kpwn_test.c](../../test/kpwn_test.c) file or the below in the command-specific documentation.

# Supported commands

The supported commands are listed in `enum kpwn_cmd`. Currently the following commands are supported:

## ALLOC_BUFFER: Kernel buffer allocation

Allocates a kernel buffer and optionally copies data from the user-space into the newly allocated buffer.

### Usage

```c
int ret;

kpwn_message msg = { .length = 1024, .gfp_account = 1 };
msg.data = malloc(msg.length);
memset(msg.data, 0x41, msg.length);

if ((ret = ioctl(fd, ALLOC_BUFFER, &msg)) == SUCCESS) {
    printf("Kernel address of the allocated buffer: %p\n", msg.kernel_ptr);
}
```

If `.gfp_account` is set to `1`, then it allocates the memory with the `GFP_KERNEL_ACCOUNT` flag, otherwise it allocates with `GPF_KERNEL`.

## KFREE: Kernel memory deallocation

Calls `kfree()` on the argument.

### Usage

```c
uint64_t kernel_address = 0xffff...;
if (ioctl(fd, KFREE, kernel_address) == SUCCESS)
    printf("Kernel address (0x%lx) was kfree()'d.\n", kernel_address);
```

## KASLR_LEAK: Get kASLR base address

Returns the kASLR adjusted virtual address of the `_text` symbol (kASLR base address for `.text` and some other sections).

### Usage

```c
uint64_t kaslr_base;
if (ioctl(fd, KASLR_LEAK, &kaslr_base) == SUCCESS)
    printf("kaslr base: %lx\n", kaslr_base);
```

## SYM_ADDR: Get any kallsyms symbol address

Returns the kASLR adjusted virtual address of the requested symbol.

Note: without `CONFIG_KALLSYMS_ALL`, only function addresses are available.

### Usage

```c
sym_addr sym_addr = { .symbol_name = "core_pattern" };
if (ioctl(fd, SYM_ADDR, &sym_addr) == SUCCESS)
    printf("core_pattern address: %lx\n", sym_addr.symbol_address);
```

## WIN_TARGET: Get a RIP target address

Gets the address of a kernel function which can be called from a ROP chain or via RIP control primitive and it prints the following text into the kernel log:

```
[    1.535654] ...
[    1.538542] kpwn: win_target was called.
[    1.538542] 
[    1.538542] !!! YOU WON !!! 
[    1.538542] 
[    1.541079] ...
```

### Usage

```c
uint64_t win_target;
if (ioctl(fd, WIN_TARGET, &kaslr_base) == SUCCESS)
    printf("win_target: %lx\n", win_target);
```

## PRINTK:

Logs the user-supplied text into the kernel logs (it is useful for maintaining the order of message coming from both user and kernel-space).

### Usage

```c
ioctl(fd, PRINTK, "hello world");
```

Which is shown in the logs as:

```
[    1.513672] hello world
```

## ARB_READ:

Copies memory from arbitrary kernel address to user-space.

### Usage

```c
sym_addr sym_addr = { .symbol_name = "core_pattern" };
if (ioctl(fd, SYM_ADDR, &sym_addr) != SUCCESS) return;

uint8_t buffer[32];
kpwn_message msg = { .length = sizeof(buffer), .data = buffer, .kernel_addr = sym_addr.symbol_addr };
if (ioctl(fd, ARB_READ, &msg) == SUCCESS) {
    printf("current core_pattern = '%s', should be same as:\n", buffer);
    system("cat /proc/sys/kernel/core_pattern");
}
```

## ARB_WRITE:

Copies memory from user-space to arbitrary kernel address.

### Usage

```c
sym_addr sym_addr = { .symbol_name = "core_pattern" };
if (ioctl(fd, SYM_ADDR, &sym_addr) != SUCCESS) return;

char new_core_pattern[] = "|/tmp/run_as_root";
kpwn_message msg = { .length = sizeof(new_core_pattern), .data = new_core_pattern, .kernel_addr = sym_addr.symbol_addr };
if (ioctl(fd, ARB_WRITE, &msg) == SUCCESS) {
    printf("core_pattern was successfully overwritten, the new value is:\n");
    system("cat /proc/sys/kernel/core_pattern");
}
```

## RIP_CONTROL: Simulate a RIP control primitive

Simulates a RIP control primitive by setting the generic CPU registers to user-provided values and then executes one of the following assembly instructions (defined in `enum rip_action`):
* `JMP_RIP`: `jmp r15`
  * `R15` is set to `rip_control_args.rip`
* `CALL_RIP`: `call r15`
  * `R15` is set to `rip_control_args.rip`
* `RET`: `ret`
  * `RSP` is expected to be set to the address of a fake stack containing e.g. a ROP chain

The following registers can be set: `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RBP`, `RSP`, `R8`, `R9`, `R10`, `R11`, `R12`, `R13`, `R14`.  (`R15` can only be set for the `RET` action, otherwise it's value is ignored and stores the call / jmp target instead.)

It needs to be explicitly specified which registers to set via the `rip_control_args.regs_to_set` field which is a bitwise OR of the `enum regs_to_set` values (see examples below).

### Usage: call a valid RIP target

```c
uint64_t win_target;
if (ioctl(fd, WIN_TARGET, &win_target) != SUCCESS) return;

rip_control_args rip = { .action = CALL_RIP, .rip = win_target };
if (ioctl(fd, RIP_CONTROL, &rip) == SUCCESS)
    printf("User-space program execution continues after executing our target function in the kernel...\n");
```

Which results in the following logs:

```
[    1.398862] kpwn: rip_control: action=0x2, rsp=0x0, value@rsp=0x0, regs_to_set=0x0, rip=0xffffffffc02e8218
[    1.401394] kpwn: win_target was called.
[    1.401394] 
[    1.401394] !!! YOU WON !!! 
[    1.401394] 
[    1.403947] kpwn: kpwn: rip_control, after asm
User-space program execution continues after executing our target function in the kernel...
```

### Usage: set RDI and jump to address

```c
rip_control_args rip = { .action = JMP_RIP, .regs_to_set = RDI, .rip = 0xffffff4141414141, .rdi = 0x4242424242424242 };
ioctl(fd, RIP_CONTROL, &rip);
```

Which results in the following crash (RIP and RDI set to the provided values):

```
[    1.434875] RIP: 0010:0xffffff4141414141                                       // RIP == 0xffffff4141414141
[    1.435939] Code: Unable to access opcode bytes at 0xffffff4141414117.
[    1.437659] RSP: 0018:ffffa6f680423ae8 EFLAGS: 00010246
[    1.439027] RAX: 0000000000000001 RBX: ffffa6f680423b28 RCX: 0000000000000000
[    1.440895] RDX: 0000000000000000 RSI: 0000000000000002 RDI: 4242424242424242  // RDI == 0x4242424242424242
```

### Usage: jump to a ROP chain by setting RSP

```c
// create ROP chain
uint64_t rop[128];
rop[0] = 0xffffff4141414141;

// store ROP chain in kernel memory
kpwn_message msg = { .length = sizeof(rop), .data = &rop };
if (ioctl(fd, ALLOC_BUFFER, &msg) != SUCCESS) return;

// jump to ROP chain by setting RSP to the ROP chain's kernel memory address
rip_control_args rip = { .action = RET, .regs_to_set = RSP, .rsp = msg.kernel_addr };
ioctl(fd, RIP_CONTROL, &rip);
```

Which results in a crash like (ROP chain item is executed):

```
[    1.381932] kpwn: rip_control: action=0x3, rsp=0xffff9e5d025e7c00, value@rsp=0xffffff4141414141, regs_to_set=0x80, rip=0x0
[    1.384801] BUG: unable to handle page fault for address: ffffff4141414141
...
[    1.396223] RIP: 0010:0xffffff4141414141
[    1.397276] Code: Unable to access opcode bytes at 0xffffff4141414117.
[    1.398991] RSP: 0018:ffff9e5d025e7c08 EFLAGS: 00010246
```

# Compilation

## Automatically with kernel-image-runner

If you run `./run.sh` with `--custom-modules=xkd_device`, the module will be compiled and loaded automatically.

## Manually for kernel-image-runner targets

Run `./compile_custom_modules.sh (kernelctf|ubuntu) <release-name> xkd_device` and after the compilation process, the compiled module can be found at `rootfs/custom_modules/xkd_device.ko`.

## Manually for custom kernels

Compile your kernel normally and then execute the following command from the same directory where you compiled your kernel (replace `<kernel-image-runner-dir>` with the root directory of the kernel-image-runner):

`make M=<kernel-image-runner-dir>/../third_party/kernel-modules/xkd_device modules`

