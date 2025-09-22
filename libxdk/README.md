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

# Installation

The library is available via a pre-compiled binary distribution or through source code compilation.

## Binary release

The most recent stable **libxdk** binary release is available for download on the **[Github releases page](https://github.com/google/kernel-research/releases)**.

This binary is **built** using **GCC 9.4.0** on **Ubuntu 20.04** to maximize compatibility. However, please be aware that compatibility issues may arise depending on your specific system environment. Should you encounter incompatibilities, recompiling the library from the **source code** is recommended (refer to the following section for details).

### Compiling sample exploits

The binary release package includes several **sample exploits**. Follow these steps to compile them:

1.  **Download and extract the latest libxdk release:**

    ```bash
    wget https://github.com/google/kernel-research/releases/download/libxdk%2Fv0.1/libxdk-v0.1.tar.gz
    tar -xzvf libxdk-v0.1.tar.gz
    ```

2.  **Go the sample folder and compile the exploit:**

    ```bash
    cd samples/exp65
    make
    ```

Upon successful execution, the **statically compiled** binary, named `exp`, will be located in the `samples/exp65` directory.

### Integrating libxdk into an existing C exploit

To integrate the **libxdk** binary release into an existing C exploit that currently compiles with a command such as:

```bash
gcc -o exp exploit.cpp -static
```

Follow these steps:
1.  **Download and extract libxdk:**
    First, download and extract the libxdk release into your exploit's project folder:

    ```bash
    wget https://github.com/google/kernel-research/releases/download/libxdk%2Fv0.1/libxdk-v0.1.tar.gz
    tar -xzvf libxdk-v0.1.tar.gz
    ```

2.  **Update the command line:**
    Use the following command line for compilation and linking:

    ```bash
    g++ -o exp exploit.cpp -static -Iinclude -Llib -lkernelXDK
    ```

    **Changes in the command line:**

      * **Compiler change:** The compiler is switched from the C compiler (`gcc`) to the **C++ compiler** (`g++`) as libxdk is a C++ library.

      * **Include paths:**
        * `-Iinclude` adds the `include` directory to the header search path.
        * `-Llib` adds the `lib` directory to the library search path.

      * **Linking:** `-lkernelXDK` links the exploit with the static library file, `libkernelXDK.a`.

## Source code compilation

### Prerequisites

The library requires the following package before compilation:

```bash
sudo apt install libkeyutils-dev
```

### Compilation

Once the prerequisite is installed, compile the core library:

```bash
./build.sh
```

This process generates the static library binary at `build/libkernelXDK.a`, ready for linking with exploits (see "Binary release" section).

### Building and running samples

To build the samples, run the following script:

```bash
./build_samples.sh
```

Successful execution will create the sample binaries, named `exp`, located within their respective directories (e.g., `samples/exp65/exp`).

**Note:** some samples require installing prerequisites, which can be done with `sudo PREREQ=1 ./build_samples.sh`.

To test a sample exploit, run the following commands:

```bash
cd samples/exp65
make test
```

## Tests

The library provides two distinct test execution scripts:

* **Local tests (`./run_local_tests.sh`)**

    This script executes a subset of tests that **do not require kernel exploitation** and can be safely run directly on your host machine.

* **Integration tests (`./run_tests.sh`)**

    This script runs the **complete test suite**, including tests that perform kernel exploitation. These tests require a VM setup, utilizing the `image_runner` tool and the `xdk_device` kernel module.

    To specify a target kernel for the integration test, use the following syntax (e.g., targeting kernelCTF's `lts-6.6.69` release):

    ```bash
    ./run_tests.sh kernelctf lts-6.6.69
    ```

### Disclaimer

This is not an officially supported Google product.