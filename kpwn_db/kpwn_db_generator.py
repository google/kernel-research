#!/usr/bin/env python3
import argparse
import re
import traceback
import logging
import sys
import os

KPWN_DB_DIR = os.path.abspath(f"{__file__}/..")
sys.path.append(KPWN_DB_DIR)

from data_model.db import Db
from data_model.meta import MetaConfig
import converter.config as config
from converter.image_db_utils import get_targets_from_image_db
from converter.kpwn_writer import KpwnWriter


def main():
  parser = argparse.ArgumentParser(
      description="Generates kpwn database from kernel-image-db database")
  parser.add_argument("--kernel-image-db-path",
                      help="Path to the kernel-image-db tool", default=f"{KPWN_DB_DIR}/../kernel-image-db")
  parser.add_argument("--release-filter", default=None,
                      help="Regex filter for which '{distro}/{release_name}' to be parsed")
  parser.add_argument("--output-path", default="target_db.kpwn",
                      help="Full file path to save target_db.kpwn")
  parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO",
                      help="Set the logging level.")
  args = parser.parse_args()

  logger = logging.getLogger(__name__)
  logger.setLevel(getattr(logging, args.log_level))
  logger.addHandler(logging.StreamHandler())

  meta = MetaConfig.from_desc(config.symbols, config.rop_actions)
  targets = get_targets_from_image_db(meta, args.kernel_image_db_path, args.release_filter, logger)
  db = Db(meta, targets)
  KpwnWriter(db).write_to_file(args.output_file)

if __name__ == "__main__":
  main()
