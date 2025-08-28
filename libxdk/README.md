A work-in-progress Linux Kernel exploitation kit, which will contain the necessary building blocks for building exploits for the Linux kernel which can target various kernel versions:

  * `[TODO]` vulnerability triggers
  * `[TODO]` kASLR leaks
  * `[TODO]` utility functions commonly used in kernel exploitations
  * `[TODO]` primitive transfers (e.g. UAF -> Arbitrary Write)
  * `[TODO]` spraying techniques (including cross-cache)
  * `[WIP]` RIP control (including stack pivots, ROP actions)
  * `[TODO]` "Exploit recipes": declarative structure how to put together the above "ingredients" to create an exploit (can be adjusted to different targets)

# Prerequisites

  * `sudo apt install libkeyutils-dev`

# Usage

Currently the exploit kit can be used by including its' source code into the exploits. Its API is not stable yet and cannot be used as a library.

Its functionality (and how it can be used) can be seen by looking at the tests (in the `test/tests` folder) and at the samples.

The samples can be built and run as:

```
make -C samples/stack_pivot_and_rop build run
```

## Tests

The tests can be run by:

* `make test`: runs the tests directly on your machine, thus only those tests will run which does not require a vulnerable target (target with the `xdk` kernel module loaded), others will fail.

* `./run_tests.sh`: runs the tests on a vulnerable target VM with the `xdk` kernel module loaded via `image_runner`, all tests will run.
