#!/usr/bin/env -S python3 -u
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import sys

PTR_SIZE = 8

def debug(msg):
  if "--debug" in sys.argv:
    sys.stderr.write(f"{msg}\n")

with open("btf.json", "rt") as f:
  btf = json.loads(f.read())

types_by_id = {s["id"]: s for s in btf["types"]}

def find_size(o):
  if "size" in o: return o["size"]
  if o["kind"] == "PTR": return PTR_SIZE
  size = find_size(types_by_id[o["type_id"]])
  return o["nr_elems"] * size if o["kind"] == "ARRAY" else size

def add_fields(fields_obj, prefix, start_offs, members_arr):
  for m in members_arr:
    debug(f"  processing field '{m['name']}'")
    field_name = f"{prefix}{m['name']}"
    t = types_by_id[m["type_id"]]
    offset = start_offs + (m["bits_offset"] // 8)

    if t["kind"] in ["STRUCT", "UNION"]:
      field_prefix = prefix if m["name"] == "(anon)" else f"{field_name}."
      add_fields(fields_obj, field_prefix, offset, t["members"])
    else:
      size = m["bitfield_size"] // 8 if "bitfield_size" in m else find_size(t)
      fields_obj[field_name] = {"offset": offset, "size": size}

structs = {}
for s in filter(lambda s: s["kind"] == "STRUCT" and s["name"] != "(anon)", btf["types"]):
  debug(f"processing struct '{s['name']}' ({s['id']})")
  structs[s["name"]] = obj = {"size": s["size"], "fields": {}}
  add_fields(obj["fields"], "", 0, s["members"])

print(json.dumps(structs, indent=4))
