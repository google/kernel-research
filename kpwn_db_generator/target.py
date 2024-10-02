"""Module containing classes related to targets."""
import os


class Target:
  """Helper class to process per-target files from kernel-image-db folders."""

  KBASE_ADDR = 0xffffffff81000000
  VERSION_TXT = "version.txt"
  SYMBOLS_TXT = "symbols.txt"
  ALL_FILES = [VERSION_TXT, SYMBOLS_TXT]

  def __init__(self, distro, release_name, dir_):
    self.distro = distro
    self.release_name = release_name
    self.dir = dir_
    self.missing_files = self.get_missing_files()

  def __str__(self):
    return f"{self.distro}/{self.release_name}"

  def file_exists(self, fn):
    return os.path.isfile(f"{self.dir}/{fn}")

  def process_file(self, fn):
    if not self.file_exists(fn):
      raise FileNotFoundError(f"{fn} file was not found for "
                              f"release: {self.release_name}")
    else:
      with open(f"{self.dir}/{fn}") as f:
        for line in f:
          yield line.strip()

  def get_version(self):
    return next(self.process_file(self.VERSION_TXT), "")

  def get_symbols(self):
    symbols = {}
    for line in self.process_file(self.SYMBOLS_TXT):
      if line[0] == " ": continue
      [addr, _, name] = line.rstrip().split(" ")
      symbols[name] = int(addr, 16) - self.KBASE_ADDR
    return symbols

  def get_missing_files(self):
    return [f for f in self.ALL_FILES if not self.file_exists(f)]
