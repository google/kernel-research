#!/usr/bin/env -S python3 -u

import re

with open("dmesg.txt", "rt") as f:
  dmesg = f.read()

crash = re.split(r"=== COMMAND-BEGIN:.*?===\n", dmesg)[1]
success = "=== COMMAND-END ===" in crash and "Attempted to kill init" in crash
if not success:
  print(f"Crashed:\n{crash}")
