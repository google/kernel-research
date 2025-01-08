# Linux kernel security research tools

This repository contains useful tools for Linux kernel security research:

* **kernel-image-db**: tools for downloading kernel various distribution release files and extracting various information from them.
   * For more details, read the [kernel-image-db/README.md](kernel-image-db/README.md) file.

* **kernel-image-runner**: tool for running various kernel distributions, with debugging and custom kernel module compilation support.
   * For more details, read the [kernel-image-runner/README.md](kernel-image-runner/README.md) file.

* **kpwn kernel module**: kernel module for simulating vulnerabilities in the kernel, tracking function calls and testing exploitation primitives.
   * For more details, read the [third_party/kernel-modules/kpwn/README.md](third_party/kernel-modules/kpwn/README.md) file.

* **kernel_rop_generator**: tools for generating ROP chains and stack pivots on Linux Kernel images.
   * For more details, read the [kernel_rop_generator/README.md](kernel_rop_generator/README.md) file.

* **expkit**: a work-in-progress Linux Kernel exploitation kit, which contains (will contain) the necessary building blocks for building exploits for the Linux kernel which can target various kernel versions.
   * For more details, read the [expkit/README.md](expkit/README.md) file.

* **kpwn_db**: a database builder which contains exploitation information (symbol addresses, ROP gadgets, stack pivots, structure field offsets) for multiple kernel targets and consumed by the exploit kit to customize exploits for targets.
   * For more details, read the [kpwn_db/README.md](kpwn_db/README.md) file.

## Disclaimer

This is not an officially supported Google product.
