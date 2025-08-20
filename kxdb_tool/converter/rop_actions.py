"""Classes handling ROP Action related logic."""

from data_model.meta import RopActionArg, RopActionMeta
from data_model.rop_chain import RopChainConstant, RopChainOffset, RopChainArgument, RopAction

class RopActionWriter:
  """Helper class to handle ROP Action writing to the db."""

  def __init__(self, rop_actions_meta):
    self.rop_actions_meta = rop_actions_meta

  def write_meta(self, wr):
    for ra in wr.list(self.rop_actions_meta):
        wr.zstr(ra.desc)                   # desc

        for arg in wr.list(ra.args):
          wr.zstr(arg.name)                # name
          wr.varuint(1 if arg.required else 0)  # flags
          if not arg.required:
            wr.varsint(arg.default_value)       # default_value

  def write_target(self, wr_target, target):
    for (wr, ra_meta) in wr_target.seekable_list(self.rop_actions_meta):
      rop_actions = {ra.description: ra for ra in target.rop_actions}
      rop_chain = rop_actions.get(ra_meta.desc)
      if not rop_chain: continue

      wr.varuint(len(rop_chain.gadgets))
      for item in rop_chain.gadgets:
        if isinstance(item, RopChainConstant):
          wr.varuint_extra(2, 0x00, item.value)
        elif isinstance(item, RopChainOffset):
          wr.varuint_extra(2, 0x01, item.kernel_offset)
        elif isinstance(item, RopChainArgument):
          wr.varuint_extra(2, 0x02, item.argument_index)
        else:
          raise TypeError("Unknown RopChainItem type")

class RopActionReader:
  """Helper class to handle ROP Action parsing from the db."""

  def read_meta(self, r):
    self.meta = []
    for _ in r.list():
      desc = r.zstr()

      args = []
      for _ in r.list():
        arg_name = r.zstr()
        flags = r.varuint()
        required = (flags & 0x01) != 0x00
        default_value = r.varsint() if not required else None
        args.append(RopActionArg(arg_name, required, default_value))

      self.meta.append(RopActionMeta(desc, args))
    return self.meta

  def read_target(self, r):
    item_types = [RopChainConstant, RopChainOffset, RopChainArgument]
    actions = []
    sizes = r.seekable_list_sizes()
    for (ra_meta, size) in zip(self.meta, sizes):
      if size == 0: continue

      items = []
      for _ in range(r.varuint()):
        (type_, value) = r.varuint_extra(2)
        if type_ >= len(item_types):
            raise TypeError(f"Unknown RopChainItem type ({type_})")
        items.append(item_types[type_](value))
      actions.append(RopAction(ra_meta.desc, items))
    return actions
