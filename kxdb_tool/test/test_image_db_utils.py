"""Tests for image_db_utils.py file."""

import logging
import unittest
import test.config as config
from converter.image_db_utils import collect_image_db_targets, get_targets_from_image_db
from converter.kxdb_writer import KxdbWriter
from data_model.db import Db
from data_model.meta import MetaConfig
from test.utils import MOCK_DB_DIR, RELEASES_DIR, expect_file, ExceptionRaisingLogger

class ImageDbUtilsTests(unittest.TestCase):
  """Tests for the image_db_utils.py file."""

  def expect_db(self, db_path, release_filter, expected_fn, expected_target_count=1):
    with expect_file(expected_fn) as f:
      meta_config = MetaConfig.from_desc(config.symbols, config.rop_actions, config.structs)
      targets = get_targets_from_image_db(meta_config, db_path, release_filter, ExceptionRaisingLogger(__name__), False, True)
      self.assertEqual(expected_target_count, len(targets))
      db = Db(meta_config, targets)
      KxdbWriter(db).write_to_file(f.name)

  def test_generate_lts_6_1_36_db(self):
    self.expect_db(MOCK_DB_DIR, "kernelctf/lts-6.1.36", "lts_6_1_36_db.kxdb")

  def test_generate_lts_6_1_38_db(self):
    self.expect_db(MOCK_DB_DIR, "kernelctf/lts-6.1.38", "lts_6_1_38_db.kxdb")

  def test_missing_files(self):
    targets = collect_image_db_targets(RELEASES_DIR, "bad/missing_files")
    self.assertEqual(1, len(targets))
    self.assertEqual("missing_files", targets[0].release_name)
    self.assertListEqual(["version.txt", "symbols.txt", "rop_actions.json",
      "stack_pivots.json", "structs.json"], targets[0].missing_files)
