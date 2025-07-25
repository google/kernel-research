#!/usr/bin/env -S python3 -u
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
import os
import sys

def read_file(fn):
  if not os.path.isfile(fn):
    raise RuntimeError(f"File not found: {fn}")

  with open(fn, "rt") as f:
    return f.read()

round_id = sys.argv[1]
tap_fn = f"test_results/round_{round_id}.txt"
dmesg_fn = f"test_results/dmesg_{round_id}.txt"

def check_tap():
  tap_results = read_file(tap_fn)
  tap_match = re.match(r"(?:^|\n)1..(\d+)(.*)\n", tap_results, re.DOTALL)
  if not tap_match:
    print("Could not find tap results in output")
    return False

  test_count = int(tap_match.group(1))
  ok_tests = set(int(test_nr) for test_nr in re.findall(r"\nok (\d+)", tap_match.group(2)))
  missing_tests = set(range(1, test_count + 1)) - ok_tests

  if missing_tests:
    print(f"The following tests were not run successfully: {', '.join(str(x) for x in sorted(missing_tests))}")

  return not missing_tests

def check_dmesg():
  dmesg = read_file(dmesg_fn)
  crash = re.split(r"=== COMMAND-BEGIN:.*?===\n", dmesg)[1]
  dmesg_success = "=== COMMAND-END ===" in crash and "Attempted to kill init" in crash
  if not dmesg_success:
    print(f"Crashed:\n{crash}")
  return dmesg_success

success = False
try:
  success = check_tap() & check_dmesg()
except Exception as e:
  print(str(e))

sys.exit(0 if success else 1)
