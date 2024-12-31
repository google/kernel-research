"""Contains tests for kpwn_db_generator."""

import contextlib
import logging
import unittest

import kpwn_db_generator
from kpwn_writer import KpwnWriter

MOCK_DB_DIR = "test/mock_db"
RELEASES_DIR = f"{MOCK_DB_DIR}/releases"


class KpwnDbGeneratorTests(unittest.TestCase):
  """Tests for the kpwn_db_generator.py file."""

  @contextlib.contextmanager
  def expect_file(self, fn):
    with open(f"test/actual_results/{fn}", "w+b") as f_actual:
      yield f_actual
      f_actual.seek(0)
      with open(f"test/expected_results/{fn}", "rb") as f_expected:
        self.assertEqual(f_expected.read(), f_actual.read())

  def expect_db(self, db_path, release_filter, expected_fn):
    with self.expect_file(expected_fn) as f:
      logger = logging.getLogger(__name__)
      logger.addHandler(logging.NullHandler())
      db = kpwn_db_generator.get_db_from_image_db(db_path, release_filter, logger)
      KpwnWriter(db).write_to_file(f.name)

  def test_generate_lts_6_1_36_db(self):
    self.expect_db(MOCK_DB_DIR, "kernelctf/lts-6.1.36", "lts_6_1_36_db.kpwn")

  def test_generate_lts_6_1_38_db(self):
    self.expect_db(MOCK_DB_DIR, "kernelctf/lts-6.1.38", "lts_6_1_38_db.kpwn")

  def test_missing_files(self):
    targets = kpwn_db_generator.collect_targets(
        RELEASES_DIR, "bad/missing_files")
    self.assertEqual(1, len(targets))
    self.assertEqual("missing_files", targets[0].release_name)
    self.assertListEqual(["version.txt", "symbols.txt", "rop_actions.json", "stack_pivots.json"],
                         targets[0].missing_files)
