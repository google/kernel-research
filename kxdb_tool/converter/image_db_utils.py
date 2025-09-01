# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import traceback

from converter.image_db_target import ImageDbTarget
from converter.utils import list_dirs
from converter.utils import natural_sort_key

def collect_image_db_targets(releases_dir, release_filter=None):
  targets = []
  for distro in list_dirs(releases_dir):
    for release_name in list_dirs(f"{releases_dir}/{distro}"):
      full_name = f"{distro}/{release_name}"
      if release_filter and not re.search(release_filter, full_name):
        continue

      target = ImageDbTarget(distro, release_name, f"{releases_dir}/{full_name}")
      targets.append(target)
  return targets

def get_targets_from_image_db(meta_config, image_db_path, release_filter, logger, allow_partial=False, allow_missing=False):
  logger.info("Collecting targets...\n")
  db_targets = collect_image_db_targets(f"{image_db_path}/releases", release_filter)
  db_targets.sort(key=lambda t: natural_sort_key(str(t)))

  if allow_partial:
    valid_targets = db_targets
  else:
    targets_with_missing_files = [t for t in db_targets if t.missing_files]
    if targets_with_missing_files:
      error_msg = "The following targets will be skipped as some of the " \
                  "required files are missing:\n"
      for target in targets_with_missing_files:
        error_msg += f" - {target.distro}/{target.release_name}: " \
                    f"{', '.join(target.missing_files)}\n"
      logger.error(error_msg)

    valid_targets = [t for t in db_targets if not t.missing_files]

  targets = []
  for db_target in valid_targets:
    logger.info(f"Processing target: {db_target}")
    try:
      targets.append(db_target.process(meta_config, allow_partial, allow_missing))
    except Exception:
      logger.error(f"Failed processing target: {traceback.format_exc()}")

  logger.info(f"Processed {len(targets)} targets.")
  return targets