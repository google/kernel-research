"""Contains tests for kpwn_db_generator."""

import logging
import unittest
from converter.kpwn_writer import KpwnWriter
import kpwn_db_generator
from test.utils import MOCK_DB_DIR, RELEASES_DIR, expect_file

class KpwnDbGeneratorTests(unittest.TestCase):
  """Tests for the kpwn_db_generator.py file."""

  def expect_db(self, db_path, release_filter, expected_fn):
    with expect_file(expected_fn) as f:
      logger = logging.getLogger(__name__)
      logger.addHandler(logging.NullHandler())
      db = kpwn_db_generator.get_db_from_image_db(db_path, release_filter, logger)
      KpwnWriter(db).write_to_file(f.name)

  def test_generate_lts_6_1_36_db(self):
    self.expect_db(MOCK_DB_DIR, "kernelctf/lts-6.1.36", "lts_6_1_36_db.kpwn")

  def test_generate_lts_6_1_38_db(self):
    self.expect_db(MOCK_DB_DIR, "kernelctf/lts-6.1.38", "lts_6_1_38_db.kpwn")

  def test_missing_files(self):
    targets = kpwn_db_generator.collect_targets(RELEASES_DIR, "bad/missing_files")
    self.assertEqual(1, len(targets))
    self.assertEqual("missing_files", targets[0].release_name)
    self.assertListEqual(["version.txt", "symbols.txt", "rop_actions.json", "stack_pivots.json"],
                         targets[0].missing_files)
