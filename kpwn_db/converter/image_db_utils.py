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

def get_targets_from_image_db(meta_config, image_db_path, release_filter, logger):
  logger.info("Collecting targets...\n")
  db_targets = collect_image_db_targets(f"{image_db_path}/releases", release_filter)
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

  targets = []
  for db_target in valid_targets:
    logger.info(f"Processing target: {db_target}")
    try:
      targets.append(db_target.process(meta_config))
    except Exception:
      logger.error(f"Failed processing target: {traceback.format_exc()}")

  logger.info(f"Processed {len(targets)} targets.")
  return targets