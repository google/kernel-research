A database builder which contains exploitation information (symbol addresses, ROP gadgets, stack pivots, structure field offsets) for multiple kernel targets and consumed by the exploit kit to customize exploits for targets.

The recommended extension for the target db file: `.kxdb`.

# Prerequisites

 * `kernel_rop_generator` (part of the kernel-researcher tools)

# Usage

```
./kxdb_tool.py
  [--kernel-image-db-path=<path to the kernel-image-db tool to add targets from>]
  [--release-filter=<regex for distro/release_name>]
  [--input-file=<full file path to the source target_db.{kxdb,json,yaml}>]
  [--output-file=<full file path to the destination target_db.{kxdb,json,yaml}>]
  [--indent=<int, json indent>]
  [--log-level=<DEBUG|INFO|WARNING|ERROR|CRITICAL>]
```

## Arguments

* `input-file` (optional): location of the current database to convert or extend. Supported file formats: kxdb, json, yaml.

* `output-file` (required): where to save the resulting database. Supported file formats: kxdb, json, yaml.

* `kernel-image-db-path` (optional): location of the `kernel-image-db` folder. If supplied then its targets will be added to the database.

* `release-filter` (optional): regex expression to filter which releases to process from `kernel-image-db`, e.g. `lts-6.1.81` or `kernelctf/lts-6.1.81` or `kernelctf/.*`. By default, there is no filter, so all downloaded releases will be part of the database.

You need to specify either `input-file` (to convert) or `kernel-image-db-path` (to build from), but you can also specify both (to extend).

If you specify `input-file` then the configuration will be reused from that file, otherwise the default configuration (from `converter/config.py` will be used.

## Example usages

Processes all downloaded releases from the `../kernel-image-db` folder and extends the `target_db.kxdb` database with these new releases:

    ./kxdb_tool.py --kernel-image-db-path ../kernel-image-db -i target_db.kxdb -o  target_db.kxdb

Processes only the `kernelctf/lts-6.1.81` release from the `../kernel-image-db/releases` folder and save the resulting database to the `../libxdk/test/artifacts/target_db_lts-6.1.81.kxdb` file:

    ./kxdb_tool.py --kernel-image-db-path ../kernel-image-db --release-filter lts-6.1.81 --output ../libxdk/test/artifacts/target_db_lts-6.1.81.kxdb


Processes all downloaded releases from `../kernel-image-db` and save the resulting database to `target_db.kxdb`:

    ./kxdb_tool.py --kernel-image-db-path ../kernel-image-db -o target_db.kxdb

Converts the database from a binary format (`.kxdb`) to JSON:

    ./kxdb_tool.py -i target_db.kxdb -o target_db.json


