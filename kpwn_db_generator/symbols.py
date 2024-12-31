class SymbolWriter:
  """Helper class to handle symbol writing to the db."""

  def __init__(self, symbols_meta):
    self.symbols_meta = symbols_meta

  def write_meta(self, wr_hdr):
    wr_hdr.u4(len(self.symbols_meta))
    for meta in self.symbols_meta:
      with wr_hdr.struct() as wr_struct:
        wr_struct.u4(meta.type_id)    # type_id
        wr_struct.zstr_u2(meta.name)  # name_len + name

  def write_target(self, wr_target, target):
    for meta in self.symbols_meta:
      wr_target.u4(target.symbols.get(meta.name, 0))

