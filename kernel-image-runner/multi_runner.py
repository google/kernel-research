#!/usr/bin/env python3
import selectors
import subprocess
import threading
import time
import os
import re
import traceback

targets_desc = "kernelctf:lts-6.1.31,lts-6.1.81,cos-97-16919.294.48,cos-101-17162.127.42,cos-105-17412.101.42,cos-109-17800.147.60,mitigation-v3-6.1.55;ubuntu:5.4.0-26.30,5.15.0-25.25,6.5.0-10.10"
#targets_desc = "kernelctf:lts-6.1.31,lts-6.1.81"


class MultiPrintLine:
  def __init__(self, mp, row_idx):
    self.mp = mp
    self.row_idx = row_idx
    self.text = ""

  def update(self, text):
    self.mp.update_line(self.row_idx, text)


class MultiPrint:
  def __init__(self):
    self.lines = []
    self.terminal_width = os.get_terminal_size().columns
    self.lock = threading.Lock()

  def add_line(self):
    print("")
    line = MultiPrintLine(self, len(self.lines))
    self.lines.append(line)
    return line

  def update_line(self, row_idx, new_text):
    new_text = new_text[0:self.terminal_width]
    shift = len(self.lines) - row_idx
    line = self.lines[row_idx]
    old_len = len(line.text)
    line.text = re.sub("\033[^m]*m", "", new_text)
    while True:
      try:
        with self.lock:
          print("\033[A" * shift + new_text + " " * (old_len - len(line.text)) + "\n" * (shift - 1))
          break
      except BlockingIOError:
        time.sleep(0.1)


def read_pipes(*pipes):
  pipes=list(pipes)
  sel = selectors.DefaultSelector()
  for pipe in pipes:
    sel.register(pipe, selectors.EVENT_READ)
  while True:
    for key, _ in sel.select():
      line = key.fileobj.readline()
      if not line: return
      yield (line[:-1], pipes.index(key.fileobj))


def run(cmd, success_exitcodes=None):
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, shell=True)
  for line, source in read_pipes(p.stdout, p.stderr):
    yield (line, source == 1)
  exitcode = p.wait()
  if exitcode not in (success_exitcodes or [0]):
    raise Exception(f"failed with error code {exitcode}")


def provide_path(fn):
  os.makedirs(os.path.dirname(fn), exist_ok=True)
  return fn

def bold_red(text):
  return f"\033[1;31m{text}\033[00m"

def bold_green(text):
  return f"\033[1;32m{text}\033[00m"

def bold_yellow(text):
  return f"\033[1;33m{text}\033[00m"

class ReleaseRunner:
  def __init__(self, multi_runner, distro, release_name):
    self.multi_runner = multi_runner
    self.distro = distro
    self.release_name = release_name
    self.title_line = multi_runner.mp.add_line()
    self.status_line = multi_runner.mp.add_line()
    multi_runner.mp.add_line()
    self.logger = open(provide_path(f"{self.multi_runner.logs_dir}/{distro}_{release_name}.log"), "wt")

  def log(self, text):
    self.logger.write(text + "\n")
    self.logger.flush()

  def update_status(self, title=None, status=None):
    # self.log(f"[+] status: {title}, {status}")
    if title is not None:
      self.title = title
      self.title_line.update(f"{self.distro} {self.release_name}: {title}")
    if status is not None:
      self.status = status
      self.status_line.update(f"  {status}")

  def run(self, cmd, success_exitcodes=[0]):
    self.log(f"[+] Running command: {cmd}")

    error = None
    lines = []
    for line, stderr in run(cmd, success_exitcodes):
      full_line = ("[STDERR] " if stderr else "") + line
      lines.append(full_line)
      self.log(full_line)
      if "error: " in line:
        error = line.split("error: ")[1]
      self.update_status(None, (bold_red("ERROR: ") if stderr else "status: ") + re.sub(r"[^\x20-\x7E]+", " ", line))

    if error is not None:
      raise Exception(error)

    return lines

  def thread_main(self):
    try:
      self.update_status("downloading release...")
      self.run(f"../kernel-image-db/download_release.sh '{self.distro}' '{self.release_name}' 'vmlinuz,modules'")

      self.update_status("compiling custom modules...")
      self.run(f"./compile_custom_modules.sh '{self.distro}' '{self.release_name}' 'kpwn'", [0, 1])

      self.update_status("running kpwn_test...")
      result = self.run(f"./run.sh {self.distro} {self.release_name} --custom-modules=keep -- /kpwn_test --pipebuf-test")
      result = '\n'.join(result)

      def find(pattern):
        m = re.findall(pattern, result)
        if not m:
          raise Exception(f"did not find pattern in result: '{pattern}'")
        return m[0]

      regs = dict(re.findall(" (R..): ([0-9a-f]+)\\b", result))
      inv_regs = {}
      for reg, value in regs.items():
        inv_regs[value] = inv_regs.get(value, []) + [reg]
      pipe_buffer_addr = find("pipe_buffer addr = 0x([0-9a-f]*)")

      self.update_status(bold_green("SUCCESS"), f"pipe_buf registers: {inv_regs.get(pipe_buffer_addr, [])}")
    except Exception as e:
      self.log("Exception:\n" + traceback.format_exc())
      self.update_status(self.title + " " + bold_red("FAILED"), bold_red("ERROR: ") + str(e))

  def start(self):
    self.update_status("starting runner...")
    self.thread = threading.Thread(target=self.thread_main)
    self.thread.start()


class MultiRunner:
  def __init__(self):
    self.mp = MultiPrint()
    self.logs_dir = "logs/"
    self.runners = []

  def add_target(self, distro, release):
    runner = ReleaseRunner(self, distro, release)
    self.runners.append(runner)

  def start(self):
    for runner in self.runners:
        runner.start()

def main():
  mr = MultiRunner()
  for distro_targets in targets_desc.split(";"):
    (distro, releases) = distro_targets.split(":")
    for release in releases.split(","):
      mr.add_target(distro, release)
  mr.start()

main()
