Tool to run scripts on various kernel images.

Requirements:
 * `sudo apt install libguestfs-tools`

Example usage:
```
./run.sh kernelctf mitigation-v3-6.1.55 slabinfo
./run.sh kernelctf mitigation-v3-6.1.55 --only-script-output slabinfo
```

Using the `--only-script-output` option will only print out the result of the script, nothing else.

Just download a kernel image without running a script:
```
./download_release.sh kernelctf lts-6.1.78
```

Running arbitrary commands on an arbitrary `vmlinuz` or `bzImage` files:
```
./run_vmlinuz.sh releases/kernelctf/lts-6.1.78/vmlinuz /scripts/slabinfo.sh
```
