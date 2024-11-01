"""Classes for writing the kpwn file format."""
from binary_writer import BinaryWriter
from rop_actions import RopActionWriter

MAGIC = "KPWN"
VERSION_MAJOR = 1
VERSION_MINOR = 0

## .kpwn file format structure
# magic = KPWN (u4)
# version_major = 0x1 (u2) - file with newer version_major
#                            is not compatible with older readers
# version_minor = 0x0 (u2) - file with newer version_minor
#                            is compatible with older readers
# meta_size (u4) - useful for older readers to skip newer metadata
# meta:
#   num_symbols (u4)
#   symbols[num_symbols]
#     struct_size (u2)
#     type_id (u4)
#     name_len (u2)
#     name[name_len] (zstr)
#   num_rop_actions (u4)
#   rop_actions[num_rop_actions]
#     struct_size (u2)
#     type_id (u4)
#     desc_len (u2)
#     desc[desc_len] (zstr)
#     num_args (u1)
#     arguments[num_args]
#       name_len (u2)
#       name[name_len] (zstr)
#       flags (u1)
#         required - 0x1
#       default_value (u8) - only if required == 0
# num_targets (u4)
# targets[num_targets]
#   struct_size (u4) - so we can jump over easily and
#                      we can add fields while keeping compatibility
#   distro_len (u2)
#   distro[distro_len] (zstr)
#   release_name_len (u2)
#   release_name[release_name_len] (zstr)
#   version_len (u2)
#   version[version_len] (zstr)
#   symbols[num_symbols]
#     offset (u4)
#   rop_actions[num_rop_actions]
#     struct_size (u2) - 0 means this ROP action is not supported
#     num_items (u1)
#     items[num_items]
#       type (b4) - enum, 0 = constant_value, 1 = symbol, 2 = argument
#       size (b4) - value is stored as 2^size
#                   (0 -> 1 byte, 1 -> 2 bytes, 2 -> 4 bytes, 3 -> 8 bytes)
#       value (depends on size)
#
# u[N] = N-byte unsigned integer (u1 = uint8_t, u4 = uint32_t)
# b[N] = N-bit unsigned integer (b4 = integer stored on 4 bits)

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


class KpwnWriter:
  """Class to write the kpwn file format."""

  def __init__(self, config, debug=False):
    self.symbol_writer = SymbolWriter(config.symbols)
    self.rop_action_writer = RopActionWriter(config.rop_actions)
    self.debug = debug

  def _write_target(self, wr_root, target):
    version = target.get_version()

    with wr_root.struct(4) as wr_target:
      wr_target.zstr_u2(target.distro)
      wr_target.zstr_u2(target.release_name)
      wr_target.zstr_u2(version)

      # symbols
      self.symbol_writer.write_target(wr_target, target)

      # ROP Actions
      self.rop_action_writer.write_target(wr_target, target)

  def write(self, f, targets):
    wr_root = BinaryWriter(f)
    wr_root.write(bytes(MAGIC, "ascii"))
    wr_root.u2(VERSION_MAJOR)
    wr_root.u2(VERSION_MINOR)

    # meta header
    with wr_root.struct(4) as wr_hdr:
      # symbols
      self.symbol_writer.write_meta(wr_hdr)

      # ROP Actions
      self.rop_action_writer.write_meta(wr_hdr)

    # targets
    wr_root.u4(len(targets))
    for target in targets:
      if self.debug:
        print(f"Processing target: {target}")
      self._write_target(wr_root, target)
