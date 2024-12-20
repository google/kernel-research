#!/usr/bin/env python3
import argparse
import os
import re
import sys
import config

sys.path.append(os.path.realpath("../kernel_rop_generator"))
from kpwn_writer import KpwnWriter
from target import Target
from utils import list_dirs
from utils import natural_sort_key


def error(msg=""):
  sys.stderr.write(f"{msg}\n")


def collect_targets(releases_dir, release_filter=None):
  targets = []
  for distro in list_dirs(releases_dir):
    for release_name in list_dirs(f"{releases_dir}/{distro}"):
      full_name = f"{distro}/{release_name}"
      if release_filter and not re.search(release_filter, full_name):
        continue

      target = Target(distro, release_name, f"{releases_dir}/{full_name}")
      targets.append(target)
  return targets


def generate_db(args, debug=False):
  if debug:
    print("Collecting targets...\n")
  targets = collect_targets(f"{args.kernel_image_db_path}/releases",
                            args.release_filter)
  targets.sort(key=lambda t: natural_sort_key(str(t)))

  targets_with_missing_files = [t for t in targets if t.missing_files]
  if debug and targets_with_missing_files:
    error("[!] The following targets will be skipped as some of the "
          "required files are missing:")
    for target in targets_with_missing_files:
      error(f" - {target.distro}/{target.release_name}: "
            f"{', '.join(target.missing_files)}")
    error()

  valid_targets = [t for t in targets if not t.missing_files]
  os.makedirs(os.path.abspath(os.path.dirname(args.output_path)), exist_ok=True)
  with open(args.output_path, "wb") as f:
    kpwn_writer = KpwnWriter(config, debug)
    kpwn_writer.write(f, valid_targets)


def main():
  parser = argparse.ArgumentParser(
      description="Generates kpwn database from kernel-image-db database")
  parser.add_argument("--kernel-image-db-path",
                      help="Path to the kernel-image-db tool", default="../kernel-image-db")
  parser.add_argument("--release-filter", default=None,
                      help="Regex filter for which '{distro}/{release_name}' to be parsed")
  parser.add_argument("--output-path", default="target_db.kpwn",
                      help="Full file path to save target_db.kpwn")
  generate_db(parser.parse_args(), True)


if __name__ == "__main__":
  main()
