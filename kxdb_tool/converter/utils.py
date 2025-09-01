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

"""Module containing simple utility methods and classes."""
import os
import re


def list_dirs(path):
  return [f.name for f in os.scandir(path) if f.is_dir()]


def natural_sort_key(s):
  """Key function for natural sorting.

  Splits a string into numeric and non-numeric parts, converting numeric parts
  to integers for comparison.

  Args:
    s: The string to sort

  Returns:
    The string split into a sortable list.
  """
  return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", s)]
