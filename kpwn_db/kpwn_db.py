#!/usr/bin/env python3
import argparse
import logging
import os
import sys


KPWN_DB_DIR = os.path.abspath(f"{__file__}/..")
sys.path.append(KPWN_DB_DIR)

from data_model.db import Db
from data_model.meta import MetaConfig
from data_model.serialization import *
import converter.config as config
from converter.image_db_utils import get_targets_from_image_db
from converter.kpwn_file import read_kpwn_db, write_kpwn_db


def main():
  parser = argparse.ArgumentParser(description=".kpwn database builder and converter")
  parser.add_argument("--kernel-image-db-path",
                      help="Path to the kernel-image-db tool to add targets from")
  parser.add_argument("--release-filter", default=None,
                      help="Regex filter for which '{distro}/{release_name}' to be parsed")
  parser.add_argument("-i", "--input-file",
                      help="Full file path to the source target_db.{kpwn,json,yaml}")
  parser.add_argument("-o", "--output-file", required=True,
                      help="Full file path to the destination target_db.{kpwn,json,yaml}")
  parser.add_argument("--indent", type=int, default=None,
                      help="How much intendation to use in JSON output file")
  parser.add_argument('--minimal', action=argparse.BooleanOptionalAction,
                      help="Minimalize output kpwn size (skip well-known meta information)")
  parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO",
                      help="Set the logging level.")
  args = parser.parse_args()

  logger = logging.getLogger(__name__)
  logger.setLevel(getattr(logging, args.log_level))
  logger.addHandler(logging.StreamHandler())

  if args.input_file:
    db = read_kpwn_db(args.input_file)
    meta = db.meta
    targets = db.targets
  elif args.kernel_image_db_path:
    meta = MetaConfig.from_desc(config.symbols, config.rop_actions)
    targets = []
  else:
    return parser.error("at least one of --input-file and --kernel_image_db_path required")

  if args.kernel_image_db_path:
    targets += get_targets_from_image_db(meta, args.kernel_image_db_path, args.release_filter, logger)

  # make targets unique
  targets = {str(t): t for t in targets}.values()

  db = Db(meta, targets)
  write_kpwn_db(args.output_file, db, indent=args.indent, minimal=args.minimal)

if __name__ == "__main__":
  main()
