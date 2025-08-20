import contextlib
import logging
import os

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
MOCK_DB_DIR = f"{TEST_DIR}/mock_db"
RELEASES_DIR = f"{MOCK_DB_DIR}/releases"
ARTIFACTS_DIR = f"{TEST_DIR}/artifacts"
ACTUAL_RESULTS_DIR = f"{TEST_DIR}/actual_results"
EXPECTED_RESULTS_DIR = f"{TEST_DIR}/expected_results"

@contextlib.contextmanager
def expect_file(fn):
  with open(f"{ACTUAL_RESULTS_DIR}/{fn}", "w+b") as f_actual:
    yield f_actual
    f_actual.seek(0)
    with open(f"{EXPECTED_RESULTS_DIR}/{fn}", "rb") as f_expected:
      if f_expected.read() != f_actual.read():
        raise Exception(f"The binary content does not match in file '{fn}' (expected len: {f_expected.tell()}, actual len: {f_actual.tell()})")

class ExceptionRaisingLogger(logging.Logger):
  def error(self, msg, *args):
    raise RuntimeError(f"Error logged: {msg % args}")