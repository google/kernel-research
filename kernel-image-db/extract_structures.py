#!/usr/bin/env -S python3 -u
import json

with open("btf.json", "rt") as f:
  btf = json.loads(f.read())

types_by_id = {s["id"]: s for s in btf["types"]}

def add_fields(fields_obj, prefix, start_offs, members_arr):
  for m in members_arr:
    field_name = f"{prefix}{m['name']}"
    t = types_by_id[m["type_id"]]
    offset = start_offs + (m["bits_offset"] // 8)

    if t["kind"] == "STRUCT":
      add_fields(fields_obj, f"{field_name}.", offset, t["members"])
    else:
      fields_obj[field_name] = {"offset": offset}

structs = {}
for s in filter(lambda s: s["kind"] == "STRUCT", btf["types"]):
  structs[s["name"]] = obj = {"size": s["size"], "fields": {}}
  add_fields(obj["fields"], "", 0, s["members"])

  last_offs = obj["size"]
  for f in reversed(obj["fields"].values()):
    f["size"] = last_offs - f["offset"]
    last_offs = f["offset"]

print(json.dumps(structs, indent=4))
