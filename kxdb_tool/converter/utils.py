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
