Tool to run scripts on various kernel images.

# Requirements
 * `sudo apt install libguestfs-tools`

# Commands

## run.sh

Downloads a Linux kernel release with and runs commands on it.

### Usage

```
./run.sh (kernelctf|ubuntu) <release-name> [--custom-modules=helloworld] [--only-command-output] [--gdb] [--snapshot] -- [<commands-to-run-in-vm>]
```

### Arguments

* `(ubuntu|kernel)` (required): supported distributions

* `<release-name>` (required): name of the release, run `./run.sh ubuntu` to list the supported release names

* `--custom-modules=helloworld,kpwn` (optional): it compiles and loads the listed custom modules. Source code of the custom kernel modules can be found in the `custom_modules/` folder.

* `--only-command-output` (optional): by default the kernel logs are also printed, but with this argument you can disable this behaviour.

* `--gdb` (optional): starts a GDB server, which makes it possible to debug the kernel.

* `--snapshot` (optional): makes the disks read-only, which is required for running multiple instances of the runner.

* `[<commands-to-run-in-vm>]` (optional): commands to run within the VM, e.g. `cat /proc/slabinfo` (which prints slabinfo and exits), or e.g. `"cat /proc/slabinfo; sh"` (which opens a shell after printing out the slabinfo).

### Custom commands / binaries

Put custom scripts, binaries into the `rootfs` folder if you'd like to make them available as `/`. So if you put `your_binary` to `./rootfs/your_binary`, then you can execute as `/your_binary` within the VM. Don't forget to `chmod u+x your_binary` (outside or inside the VM).

### Running commands as non-root user

A non-root `user` user is available within the VM. You can use `su user` to spawn a shell as `user` or `su user -c '<commands>'` to run commands as `user`, e.g. `su user -c 'id'`.

### Example usages

* Opens a shell on an `ubuntu` `5.4.0-26.30` release:
```
./run.sh ubuntu 5.4.0-26.30
```

* Run `cat /proc/slabinfo` on `kernelctf` `mitigation-v3-6.1.55` release and exits:
```
./run.sh kernelctf mitigation-v3-6.1.55 -- cat /proc/slabinfo
```

* Same, but only shows the output of the `slabinfo` and no kernel messages if you use ` --only-script-output`:
```
./run.sh kernelctf mitigation-v3-6.1.55 --only-script-output -- cat /proc/slabinfo
```

* Same, but instead of exiting, spawns a shell too:
```
./run.sh kernelctf mitigation-v3-6.1.55 -- "cat /proc/slabinfo; sh"
```

* Create a flag file as root and try to cat as non-root `user` (which fails with `Permission denied`):

```
./run.sh kernelctf mitigation-v3-6.1.55 -- "echo FLAGSECRET > /flag; chmod 0000 /flag; echo as root:; cat flag; su user -c 'whoami; id; echo as user:; cat /flag'"
```

* Execute a custom binary (no libc is available on the VM, so please use statically compiled binaries):

```
gcc -static -o main main.c
cp main rootfs/
./run.sh kernelctf mitigation-v3-6.1.55 /main
```

## run_vmlinuz.sh

Running arbitrary commands on arbitrary `vmlinuz` or `bzImage` files.

### Usage

```
./run_vmlinuz.sh <vmlinuz-path> [--modules-path=<...>] [--gdb] [--snapshot] [--only-print-output-file] -- [<commands-to-run-in-vm>]
```

### Arguments

* `<vmlinuz-path>` (required): path to the `vmlinuz` or `bzImage` file

* `--modules-path` (optional): path to the root filesystem which contains the kernel modules (which were built for the kernel). This path should contain a `lib/modules/<release>/` folder which contains the module structure. See `run.sh` how to use this argument.

* See `run.sh` usage for the description of the other parameters.

### Example usage

```
./run_vmlinuz.sh ../kernel-image-db/releases/kernelctf/lts-6.1.72/vmlinuz -- cat /proc/slabinfo
```
