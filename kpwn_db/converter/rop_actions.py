"""Classes handling ROP Action related logic."""

import math
from data_model.rop_chain import RopChainConstant, RopChainOffset, RopChainArgument

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
      rop_actions = {ra.type_id: ra for ra in target.rop_actions}
      with wr_target.struct() as wr:
        rop_chain = rop_actions.get(ra_meta.type_id)
        if not rop_chain: continue

        wr.varuint(len(rop_chain.gadgets))
        for item in rop_chain.gadgets:
          if isinstance(item, RopChainConstant):
            wr.varuint(0x00 | (item.value << 2))
          elif isinstance(item, RopChainOffset):
            wr.varuint(0x01 | (item.kernel_offset << 2))
          elif isinstance(item, RopChainArgument):
            wr.varuint(0x02 | (item.argument_index << 2))
          else:
            raise TypeError("Unknown RopChainItem type")
