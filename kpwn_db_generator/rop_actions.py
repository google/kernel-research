"""Classes handling ROP Action related logic."""

import math
from rop_chain import *

class RopActionWriter:
  """Helper class to handle ROP Action writing to the db."""

  def __init__(self, rop_actions_meta):
    self.rop_actions_meta = rop_actions_meta

  def write_meta(self, wr_hdr):
    wr_hdr.u4(len(self.rop_actions_meta))
    for ra in self.rop_actions_meta:
      with wr_hdr.struct() as wr:
        wr.u4(ra.type_id)                  # type_id
        wr.zstr_u2(ra.desc)                # desc_len + desc

        wr.u1(len(ra.args))                # num_args
        for arg in ra.args:
          wr.zstr_u2(arg.name)             # name_len + name
          wr.u1(1 if arg.required else 0)  # flags
          if not arg.required:
            wr.u8(arg.default_value)       # default_value

  def write_target(self, wr_target, target):
    for ra_meta in self.rop_actions_meta:
      with wr_target.struct() as wr:
        rop_chain = target.rop_actions.get(ra_meta.type_id)
        if not rop_chain: continue

        wr.u1(len(rop_chain.items))
        for item in rop_chain.items:
          item_type = None
          value = None
          if isinstance(item, RopChainConstant):
            item_type = 0
            value = item.value
          elif isinstance(item, RopChainOffset):
            item_type = 1
            value = item.kernel_offset
          elif isinstance(item, RopChainArgument):
            item_type = 2
            value = item.argument_index
          else:
            raise TypeError("Unknown RopChainItem type")

          byte_count = math.ceil(math.log((value if value else 1) + 1, 256))
          # value is stored as 2^size
          byte_count_log = math.ceil(math.log(byte_count, 2))
          # 1 -> 1, 2 -> 2, 3..4 -> 4, 5..8 -> 8
          byte_count = 2 ** byte_count_log
          wr.u1((item_type << 4) | byte_count_log)
          wr.uint(byte_count, value)
