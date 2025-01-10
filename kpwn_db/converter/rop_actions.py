"""Classes handling ROP Action related logic."""

from data_model.meta import RopActionArg, RopActionMeta
from data_model.rop_chain import RopChainConstant, RopChainOffset, RopChainArgument, RopAction

class RopActionWriter:
  """Helper class to handle ROP Action writing to the db."""

  def __init__(self, rop_actions_meta):
    self.rop_actions_meta = rop_actions_meta

  def write_meta(self, wr_hdr, minimal=False):
    wr_hdr.u4(len(self.rop_actions_meta))
    for ra in self.rop_actions_meta:
      with wr_hdr.struct() as wr:
        wr.u4(ra.type_id)                  # type_id
        if minimal:
          continue
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

class RopActionReader:
  """Helper class to handle ROP Action parsing from the db."""

  def read_meta(self, r_hdr):
    self.meta = []
    for _ in range(r_hdr.u4()):
      r = r_hdr.struct()
      type_id = r.u4()
      desc = r.zstr_u2()

      args = []
      for _ in range(r.u1()):
        name = r.zstr_u2()
        flags = r.u1()
        required = (flags & 0x01) != 0x00
        default_value = r.u8() if not required else None
        args.append(RopActionArg(name, required, default_value))

      self.meta.append(RopActionMeta(type_id, desc, args))
    return self.meta

  def read_target(self, r_target):
    item_types = [RopChainConstant, RopChainOffset, RopChainArgument]
    actions = []
    for ra_meta in self.meta:
      r = r_target.struct()
      if not r: continue

      items = []
      for _ in range(r.varuint()):
        type_and_value = r.varuint()
        type_ = type_and_value & 0x03
        value = type_and_value >> 2
        if type_ >= len(item_types):
            raise TypeError(f"Unknown RopChainItem type ({type_})")
        items.append(item_types[type_](value))
      actions.append(RopAction(ra_meta.type_id, ra_meta.desc, items))
    return actions
