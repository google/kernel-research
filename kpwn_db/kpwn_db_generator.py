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
from converter.kpwn_writer import KpwnWriter
from converter.image_db_target import ImageDbTarget
from converter.utils import list_dirs
from converter.utils import natural_sort_key

def collect_targets(releases_dir, release_filter=None):
  targets = []
  for distro in list_dirs(releases_dir):
    for release_name in list_dirs(f"{releases_dir}/{distro}"):
      full_name = f"{distro}/{release_name}"
      if release_filter and not re.search(release_filter, full_name):
        continue

      target = ImageDbTarget(distro, release_name, f"{releases_dir}/{full_name}")
      targets.append(target)
  return targets


def get_db_from_image_db(image_db_path, release_filter, logger):
  logger.info("Collecting targets...\n")
  db_targets = collect_targets(f"{image_db_path}/releases", release_filter)
  db_targets.sort(key=lambda t: natural_sort_key(str(t)))

  targets_with_missing_files = [t for t in db_targets if t.missing_files]
  if targets_with_missing_files:
    error_msg = "The following targets will be skipped as some of the " \
                "required files are missing:\n"
    for target in targets_with_missing_files:
      error_msg += f" - {target.distro}/{target.release_name}: " \
                   f"{', '.join(target.missing_files)}\n"
    logger.error(error_msg)

  valid_targets = [t for t in db_targets if not t.missing_files]
  meta_config = MetaConfig.from_desc(config.symbols, config.rop_actions)

  targets = []
  for db_target in valid_targets:
    logger.info(f"Processing target: {db_target}")
    try:
      targets.append(db_target.process(meta_config))
    except Exception:
      logger.error(f"Failed processing target: {traceback.format_exc()}")

  logger.info(f"Processed {len(targets)} targets.")
  return Db(meta_config, targets)


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

  db = get_db_from_image_db(args.kernel_image_db_path, args.release_filter, logger)
  KpwnWriter(db).write_to_file(args.output_path)

if __name__ == "__main__":
  main()
