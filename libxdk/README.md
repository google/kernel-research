# What is libxdk?

`libxdk` is the **main component** of the **kernelXDK**. It's a C++ library designed to be linked with exploit code, providing the following features:

  * **Target Detection:** Detect the target environment the exploit is running on (currently supports **kernelCTF** targets).

  * **Symbol and Structure Information:** Provide symbols, structure and field information specific to the target.

  * **ROP Payload Generation:** Generate ROP payloads for privilege escalation and escaping namespaces and sandboxes.

  * **Payload Layout Planner:** Finds the right **stack pivoting** gadgets.

  * **Convenience Functions:** Offer functions for commonly used exploit functionality.

### Planned Features

The following functionalities are not yet implemented but are planned for future releases:

  * **EntryBleed** and **prefetch**-based KASLR leaks.

  * Smaller utilities like **namespace setup**, **CPU pinning**, and **communication between threads**.

  * **Spraying support** with features like **limit bypassing**, **leaking**, **victim object identification**, **cross-cache**, and **Dirty PageTable** support.

  * `core_pattern` **overwrite** and eBPF-based **shellcode spraying**.

# Usage

The library can be used either by downloading the binary release version or directly compiling from the source code.

## Using the binary release version

The latest libxdk version can be downloaded from the [Github releases page](https://github.com/google/kernel-research/releases).

This release is [built](https://github.com/google/kernel-research/blob/main/.github/workflows/release-libxdk.yml#L54) with GCC 9.4.0 on Ubuntu 20.04 to increase compatability, but it is possible that it won't work on your system and you need to recompile the library from source code in case of incompability issues.



## Prerequisites

  * `sudo apt install libkeyutils-dev`

Currently the exploit kit can be used by including its' source code into the exploits. Its API is not stable yet and cannot be used as a library.

Its functionality (and how it can be used) can be seen by looking at the tests (in the `test/tests` folder) and at the samples.

The samples can be built and run as:

```
make -C samples/pipe_buf_rop build run
```

## Tests

The tests can be run by:

* `make test`: runs the tests directly on your machine, thus only those tests will run which does not require a vulnerable target (target with the `xdk` kernel module loaded), others will fail.

* `./run_tests.sh`: runs the tests on a vulnerable target VM with the `xdk` kernel module loaded via `image_runner`, all tests will run.
