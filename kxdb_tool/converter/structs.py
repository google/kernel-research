"""Classes handling Struct related logic."""

from data_model.meta import StructFieldMeta, StructMeta
from data_model.structs import StructField, Struct

class StructWriter:
  """Helper class to handle Struct writing to the db."""

  def __init__(self, structs_meta):
    self.structs_meta = sorted(structs_meta, key=lambda x: x.struct_name)
    self.struct_layouts = []

  def write_meta(self, wr_meta):
    for (wr, s) in wr_meta.seekable_list(self.structs_meta):
      wr.zstr(s.struct_name)
      for f in wr.list(s.fields):
        wr.zstr(f.field_name)
        wr.u1(f.optional)

  def write_target(self, wr_target, target):
    with wr_target.struct() as wr:
      for (meta_idx, struct_meta) in enumerate(self.structs_meta):
        struct = target.structs.get(struct_meta.struct_name, None)
        if struct:
          struct.meta_idx = meta_idx
          try:
            idx = self.struct_layouts.index(struct)
          except ValueError:
            idx = len(self.struct_layouts)
            self.struct_layouts.append(struct)
        else:
          idx = -1
        wr.varuint(idx + 1)

  def write_struct_layouts(self, root_wr):
    for (wr, struct) in root_wr.seekable_list(self.struct_layouts):
      wr.varuint(struct.meta_idx)
      wr.varuint(struct.size)
      struct_meta = self.structs_meta[struct.meta_idx]
      for field_meta in struct_meta.fields:
        field = struct.fields.get(field_meta.field_name)
        if field is None:
          if not field_meta.optional:
            raise RuntimeError(f"Non-optional field is missing: {struct_meta.struct_name}.{field_meta.field_name}")
          wr.varuint(0)
        else:
          wr.varuint(field.offset + 1)
          wr.varuint(field.size)


class StructReader:
  """Helper class to handle Struct parsing from the db."""

  def read_meta(self, r_hdr):
    self.meta = []
    for _ in r_hdr.seekable_list():
      struct_name = r_hdr.zstr()
      fields = []
      for _ in r_hdr.list():
        field_name = r_hdr.zstr()
        optional = r_hdr.u1()
        fields.append(StructFieldMeta(field_name, optional == 1))
      self.meta.append(StructMeta(struct_name, fields))
    return self.meta

  def read_struct_layouts(self, r_root, struct_layouts_db_offset):
    self.struct_layouts = []
    with r_root.seek(struct_layouts_db_offset):
      for _ in r_root.seekable_list():
        meta_idx = r_root.varuint()
        sizeof = r_root.varuint()
        fields = {}
        for field_meta in self.meta[meta_idx].fields:
          offset = r_root.varuint() - 1
          if offset == -1:  # missing field
            if not field_meta.optional:
              raise RuntimeError(f"Non-optional field is missing: {field_meta.field_name}")
            continue
          size = r_root.varuint()
          fields[field_meta.field_name] = StructField(offset=offset, size=size)
        self.struct_layouts.append(Struct(meta_idx=meta_idx, size=sizeof, fields=fields))
    return self.struct_layouts

  def read_target(self, r_target):
    r = r_target.struct()
    structs = {}
    for struct_meta in self.meta:
      layout_idx = r.varuint() - 1
      if layout_idx == -1:
        continue
      structs[struct_meta.struct_name] = self.struct_layouts[layout_idx]
    return structs

