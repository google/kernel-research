"""Module containing classes related to targets."""
import re

class Target:
  """Contains all target specific information"""

  def __init__(self, distro, release_name, version, symbols, rop_actions, stack_pivots):
    self.distro = distro
    self.release_name = release_name
    self.version = version
    # dict: name -> offset
    self.symbols = symbols
    # dict: type_id -> RopChain
    self.rop_actions = rop_actions
    # Pivots
    self.stack_pivots = stack_pivots

  def __str__(self):
    return f"{self.distro}/{self.release_name}"

class SymbolMeta:
  def __init__(self, type_id, name):
    self.type_id = type_id
    self.name = name

class RopActionArg:
  def __init__(self, name, default_value=None):
    self.name = name
    self.default_value = default_value
    self.required = default_value is None

class RopActionMeta:
  def __init__(self, type_id, desc, args):
    self.type_id = type_id
    self.desc = desc
    self.args = args

  def __repr__(self) -> str:
    return self.desc
  
  def from_config(type_id, desc):
    ARG_PATTERN = r"ARG_([a-z0-9_]+)(?:=(0x[0-9a-fA-F]+|[0-9]+))?"

    args = []
    for name, default_value in re.findall(ARG_PATTERN, desc):
      args.append(RopActionArg(name, int(default_value, 0) if default_value else None))

    return RopActionMeta(type_id, desc, args)

class MetaConfig:
  def __init__(self, symbols, rop_actions):
    self.symbols = symbols
    self.rop_actions = rop_actions

  def from_desc(symbols={}, rop_actions={}):
    symbols_meta = [SymbolMeta(type_id, name) for (type_id, name) in symbols.items()]
    rop_actions_meta = list(map(lambda x: RopActionMeta.from_config(x[0], x[1]),
                                rop_actions.items()))
    return MetaConfig(symbols_meta, rop_actions_meta)
  
class Db:
  def __init__(self, meta, targets):
    self.meta = meta
    self.targets = targets