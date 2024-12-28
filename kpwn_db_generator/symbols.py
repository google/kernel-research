class SymbolWriter:
  """Helper class to handle symbol writing to the db."""

  def __init__(self, symbols_config):
    self.symbols_config = symbols_config

  def write_meta(self, wr_hdr):
    wr_hdr.u4(len(self.symbols_config))
    for [type_id, name] in self.symbols_config.items():
      with wr_hdr.struct() as wr_struct:
        wr_struct.u4(type_id)    # type_id
        wr_struct.zstr_u2(name)  # name_len + name

  def write_target(self, wr_target, target):
    target_symbols = target.get_symbols()
    for name in self.symbols_config.values():
      wr_target.u4(target_symbols.get(name, 0))
