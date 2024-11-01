"""Contains tests for kpwn_db_generator."""

import contextlib
import types
import unittest
import kpwn_db_generator


MOCK_DB_DIR = "test/mock_db"
RELEASES_DIR = f"{MOCK_DB_DIR}/releases"


class KpwnDbGeneratorTests(unittest.TestCase):
  """Tests for the kpwn_db_generator.py file."""

  @contextlib.contextmanager
  def expect_file(self, fn):
    with open(f"test/actual_results/{fn}", "r+b") as f_actual:
      yield f_actual
      f_actual.seek(0)
      with open(f"test/expected_results/{fn}", "rb") as f_expected:
        self.assertEqual(f_expected.read(), f_actual.read())

  def expect_db(self, args, expected_fn):
    with self.expect_file(expected_fn) as f:
      kpwn_db_generator.generate_db(
          types.SimpleNamespace(**args, output_path=f.name))

  def test_generate_lts_6_1_36_db(self):
    self.expect_db({
        "kernel_image_db_path": MOCK_DB_DIR,
        "release_filter": "kernelctf/lts-6.1.36",
    }, "lts_6_1_36_db.kpwn")

  def test_missing_files(self):
    targets = kpwn_db_generator.collect_targets(
        RELEASES_DIR, "bad/missing_files")
    self.assertEqual(1, len(targets))
    self.assertEqual("missing_files", targets[0].release_name)
    self.assertListEqual(["version.txt", "symbols.txt", "rop_actions.json"],
                         targets[0].missing_files)
