# Linux kernel security research tools

This repository contains useful tools for Linux kernel security research:

* **kernel-image-db**: tools for downloading kernel various distribution release files and extracting various information from them.
   * For more details, read the [kernel-image-db/README.md](kernel-image-db/README.md) file.

* **kernel-image-runner**: tool for running various kernel distributions, with debugging and custom kernel module compilation support.
   * For more details, read the [kernel-image-runner/README.md](kernel-image-runner/README.md) file.

* **xdk_device**: kernel module for simulating vulnerabilities in the kernel, tracking function calls and testing exploitation primitives.
   * For more details, read the [third_party/kernel-modules/xdk_device/README.md](third_party/kernel-modules/xdk_device/README.md) file.

* **kernel_rop_generator**: tools for generating ROP chains and stack pivots on Linux Kernel images.
   * For more details, read the [kernel_rop_generator/README.md](kernel_rop_generator/README.md) file.

* **libxdk**: a work-in-progress Linux Kernel exploitation kit, which contains (will contain) the necessary building blocks for building exploits for the Linux kernel which can target various kernel versions.
   * For more details, read the [libxdk/README.md](libxdk/README.md) file.

* **kxdb_tool**: a database builder which contains exploitation information (symbol addresses, ROP gadgets, stack pivots, structure field offsets) for multiple kernel targets and consumed by the exploit kit to customize exploits for targets.
   * For more details, read the [kxdb_tool/README.md](kxdb_tool/README.md) file.

## Reporting Bugs

If you find a bug, please help us by [submitting an issue](https://github.com/google/kernel-research/issues/new) on GitHub.

Before you create a new issue, please check the existing ones to see if your bug has already been reported.

When reporting a bug, please include:
* A clear and descriptive title
* Steps to reproduce the behavior
* Expected vs. actual behavior
* Any screenshots or code snippets that might be helpful
* If relevant, details about your OS, installed libraries, compiler toolchain, the target kernel image (distro + release).

_Note: this project is currently in a **beta state**. We are focused on core development, so bug fixes may take some time or may not happen at all. We appreciate your patience and understanding._

## Disclaimer

This is not an officially supported Google product.
