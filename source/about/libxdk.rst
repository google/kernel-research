libXDK
======

A work-in-progress Linux Kernel exploitation kit, which will contain the necessary building blocks for building exploits for the Linux kernel which can target various kernel versions.

---

Prerequisites
-------------

* ``sudo apt install libkeyutils-dev``

---

Build/Usage
-----

TODO: Explain Build and Usage

---

Modules
-----

TODO: Module explained with links to the API

---

Tests
-----

The tests can be run by:

* ``make test``: runs the tests directly on your machine, thus only those tests will run which does not require a vulnerable target (target with the ``kpwn`` kernel module loaded), others will fail.

* ``./run_tests.sh``: runs the tests on a vulnerable target VM with the ``kpwn`` kernel module loaded via ``image_runner``, all tests will run.
