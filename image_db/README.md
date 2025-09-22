# Kernel Image DB

Tools for downloading kernel various distribution release files and extracting various information from them.

## Prerequisites

 * `curl`
 * for processing debug symbols: `bpftool`, `jq`, `pahole`, `nm`, `ROPgadget`

## download_release.sh

Downloads Linux kernel distribution files:
  * runnable image (`vmlinuz` file)
  * kernel module binaries (`linux-modules/`, includes a root partition `/` folder structure)
  * debugging symbols (unstripped `vmlinux` file)
  * kernel headers for custom module compilation (`linux-headers-for-module/` directory)

If the debugging symbols are downloaded then the following information are also extracted about the release:
  * `btf.json`, `btf_formatted.json`: BTF information as JSON
  * `pahole.txt`: structs information
  * `symbols.txt`: kernel symbols
  * `.config`: kernel configuration
  * `rop_gadgets.txt`: available ROP gadgets

### Supported distributions

  * kernelCTF
  * Ubuntu

### Usage

```
./download_release.sh (kernelctf|ubuntu) (list|<release-name>) (vmlinuz|dbgsym|headers|modules|all)
```

### Arguments

* `(ubuntu|kernelctf)` (required): selected distribution

* `<release-name>` (required): name of the release, run `./download_release.sh (ubuntu|kernelctf) list` to list the supported release names

* `(vmlinuz|dbgsym|headers|modules|all)` (required if release was selected):
  * `vmlinuz`: downloads runnable `vmlinuz` image
  * `modules`: downloads kernel module binaries
  * `dbgsym`: downloads debugging symbols (unstripped `vmlinux` file)
  * `headers`: downloads kernel headers (for custom module compilation)
  * `all`: downloads all above

  * Multiple options can be selected by separating them with a comma, e.g. `vmlinuz,modules` downloads the `vmlinuz` file and the kernel modules.

### Example usages

#### List available Ubuntu releases

```
./download_release.sh ubuntu list
```

#### Downloads Ubuntu release `5.15.0-118.128` with `vmlinuz` file and kernel modules

```
./download_release.sh ubuntu 5.15.0-118.128 vmlinuz,modules
```

The downloaded `vmlinuz` file and `linux-headers-for-module/` folder can be found under the `./releases/ubuntu/5.15.0-118.128/` folder.

## collect_runtime_data.sh

Use `image_runner` to extract runtime information for the already downloaded releases (after calling `download_release.sh`):

 * `version.txt`: contents of `/proc/version` (similar to `uname -a`)

 * `slabinfo.txt`: contents of `/proc/slabinfo` (slab cache information)

### Usage

```
./collect_runtime_data.sh
```

There are no arguments, it runs on all downloaded releases, but only extracts the information if it was not extracted before (otherwise the release is skipped).

## collect.sh

Downloads all releases listed in `releases.yaml`.

### Usage

```
./collect.sh
```

There are no arguments.

### Disclaimer

This is not an officially supported Google product.