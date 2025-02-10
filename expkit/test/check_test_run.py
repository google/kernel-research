#!/usr/bin/env -S python3 -u
import re
import sys

def read_file(fn):
  with open(fn, "rt") as f:
    return f.read()

def check_tap():
  tap_results = read_file("tap_results.txt")
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
  dmesg = read_file("dmesg.txt")
  crash = re.split(r"=== COMMAND-BEGIN:.*?===\n", dmesg)[1]
  dmesg_success = "=== COMMAND-END ===" in crash and "Attempted to kill init" in crash
  if not dmesg_success:
    print(f"Crashed:\n{crash}")
  return dmesg_success

success = check_tap() & check_dmesg()

sys.exit(0 if success else 1)
