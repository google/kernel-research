A database builder which contains exploitation information (symbol addresses, ROP gadgets, stack pivots, structure field offsets) for multiple kernel targets and consumed by the exploit kit to customize exploits for targets.

The recommended extension for the target db file: `.kpwn`.

# Prerequisites

 * `kernel_rop_generator` (part of the kernel-researcher tools)

# Usage

```
./kpwn_db_generator.py
  [--kernel-image-db-path=<location of kernel-image-db>]
  [--release-filter=<regex for distro/release_name>]
  [--output-path=<where to save target_db.kpwn>]
```

## Arguments

* `kernel-image-db-path` (optional): location of the `kernel-image-db` folder, `../kernel-image-db` by default.

* `release-filter` (optional): regex expression to filter which releases to process from `kernel-image-db`, e.g. `lts-6.1.81` or `kernelctf/lts-6.1.81` or `kernelctf/.*`. By default, there is no filter, so all downloaded releases will be part of the database.

* `output-path` (optional): where to save the resulting database, by default it will be saved to `target_db.kpwn`.

## Example usages

* `./kpwn_db_generator.py`

  * Processes all downloaded releases from `../kernel-image-db` and save the resulting database to `target_db.kpwn`.

* `./kpwn_db_generator.py --kernel-image-db-path ../kernel-image-db --release-filter lts-6.1.81 --output-path ../expkit/test/artifacts/target_db_lts-6.1.81.kpwn`

  * Processes only the `kernelctf/lts-6.1.81` release from the `../kernel-image-db/releases` folder and save the resulting database to the `../expkit/test/artifacts/target_db_lts-6.1.81.kpwn` file.

