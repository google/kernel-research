#!/usr/bin/env python3
import argparse
import glob
import logging
import os
import sys
import re
import pprint

KXDB_DIR = os.path.abspath(f"{__file__}/..")
sys.path.append(KXDB_DIR)

from data_model.db import Db
from data_model.meta import MetaConfig
from data_model.serialization import *
import converter.config as config
from converter.image_db_utils import get_targets_from_image_db
from converter.kpwn_file import read_kpwn_db, write_kpwn_db
from converter.partial_sync import PartialSync

def main():
  parser = argparse.ArgumentParser(description=".kxdb database builder and converter")
  parser.add_argument("--kernel-image-db-path",
                      help="Path to the kernel-image-db tool to add targets from")
  parser.add_argument("--release-filter", default=None,
                      help="Regex filter for which '{distro}/{release_name}' to be saved in the output database")
  parser.add_argument("--release-filter-add", default=None,
                      help="Regex filter for which '{distro}/{release_name}' to be added to the database")
  parser.add_argument("-i", "--input-file",
                      help="Full file path to the source target_db.{kpwn,json,yaml}")
  parser.add_argument("-o", "--output-file", default=None,
                      help="Full file path to the destination target_db.{kpwn,json,yaml}")
  parser.add_argument("--indent", type=int, default=None,
                      help="How much intendation to use in JSON output file")
  parser.add_argument('--list-targets', action='store_true',
                      help="List the targets in the database")
  parser.add_argument('--partial-sync', action='store_true',
                      help="Only add missing data to the database")
  parser.add_argument('--partial-list-files', action='store_true',
                      help="List missing files for partial sync")
  parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO",
                      help="Set the logging level.")
  args = parser.parse_args()

  logger = logging.getLogger(__name__)
  logger.setLevel(getattr(logging, args.log_level))
  logger.addHandler(logging.StreamHandler())

  default_config = MetaConfig.from_desc(config.symbols, config.rop_actions, config.structs)

  db_config = None
  targets = []
  if args.input_file:
    input_files = sorted(glob.glob(args.input_file, recursive=True))
    for input_file in input_files:
      logger.info("Processing input file: %s", input_file)
      db = read_kpwn_db(input_file)
      if db_config and db_config != db.meta:
        with open("old_config.txt", "wt") as f: f.write(pprint.pformat(db_config))
        with open("new_config.txt", "wt") as f: f.write(pprint.pformat(db.meta))
        sys.stderr.write(f"Error: all input files must have the same config\nDiff:\n")
        os.system("diff old_config.txt new_config.txt 1>&2")
        os._exit(1)
      db_config = db.meta
      targets += db.targets
    new_config = db_config
  elif args.kernel_image_db_path:
    new_config = default_config
  else:
    return parser.error("at least one of --input-file or --kernel_image_db_path required")

  if args.partial_sync:
    new_config = default_config  # upgrade the db_config

  partial_sync = PartialSync(db_config, default_config)

  if args.partial_list_files:
    missing_files = partial_sync.get_missing_files()
    if missing_files:
      print(' '.join(missing_files))
    sys.exit(0 if missing_files else 1)

  if args.kernel_image_db_path:
    new_targets = get_targets_from_image_db(new_config, args.kernel_image_db_path, args.release_filter_add, logger, args.partial_sync, True)
    if not new_targets:
      sys.stderr.write("No new targets to add. Exiting...\n")
      sys.exit(1)

    if args.partial_sync:
      partial_sync.sync(targets, new_targets, logger)
    else:
      # add new targets, but make sure they are unique
      targets = {str(t): t for t in new_targets + targets}.values()

  if args.release_filter:
    targets = [t for t in targets if re.search(args.release_filter, f"{t.distro}/{t.release_name}")]

  if args.list_targets:
    for t in targets:
      print(f"{t.distro}/{t.release_name}")
    sys.exit(0)

  db = Db(new_config, targets)

  if args.output_file:
    write_kpwn_db(args.output_file, db, indent=args.indent)
  else:
    return parser.error("at least one of --output-file or --list-targets or --partial-list-files required")

if __name__ == "__main__":
  main()
