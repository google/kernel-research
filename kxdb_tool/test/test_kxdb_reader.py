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

"""Contains tests for KxdbWriter."""

import unittest
from converter.kxdb_reader import KxdbReader
from data_model.db import Db
from data_model.meta import MetaConfig
from test.utils import RELEASES_DIR, ARTIFACTS_DIR, expect_file
from data_model.serialization import to_json

class KxdbReaderTests(unittest.TestCase):
  """Tests for the KxdbReader class."""

  def run_db_test(self, fn):
    db = KxdbReader().read_from_file(f"{ARTIFACTS_DIR}/{fn}.kxdb")
    db_json = to_json(db, indent=4)
    with expect_file(f"{fn}.json") as f:
      f.write(db_json.encode("utf-8"))

  def test_lts_6_1_36(self):
    self.run_db_test("lts_6_1_36_db")

  def test_lts_6_1_38(self):
    self.run_db_test("lts_6_1_38_db")
