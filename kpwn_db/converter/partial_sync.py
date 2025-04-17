"""Module containing classes related to add missing partial data to database."""
from converter.image_db_target import ImageDbTarget


class PartialSync:
  def __init__(self, old_config, new_config):
    self.old_config = old_config
    self.new_config = new_config

  def get_missing_files(self):
    configs = {
      "symbols": ImageDbTarget.SYMBOLS_TXT,
      "rop_actions": ImageDbTarget.ROP_ACTIONS_JSON,
      "structs": ImageDbTarget.STRUCTS_JSON
    }

    missing_files = []
    for prop, fn in configs.items():
      new = getattr(self.new_config, prop)
      old = getattr(self.old_config, prop)
      missing_items = [item for item in new if item not in old]
      if missing_items:
        missing_files.append(fn)

    return missing_files

  def sync(self, old_targets, new_targets, logger):
    by_version = {str(t): t for t in new_targets}

    for target in old_targets:
      new_target = by_version.get(str(target))
      if not new_target:
        logger.error(f"Target cannot be upgraded as new target was not found: {target}")
        continue

      for key, value in vars(new_target).items():
        if value:
          setattr(target, key, value)
