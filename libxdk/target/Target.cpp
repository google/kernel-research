// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <xdk/target/Target.h>
#include <cstdint>
#include <map>
#include <string>
#include <cstring>
#include <xdk/util/error.h>

std::map<RopActionId, std::string> RopActionNames {
    { RopActionId::MSLEEP, "msleep" },
    { RopActionId::COMMIT_INIT_TASK_CREDS, "commit_creds" },
    { RopActionId::SWITCH_TASK_NAMESPACES, "switch_task_namespaces" },
    { RopActionId::WRITE_WHAT_WHERE_64, "write_what_where_64" },
    { RopActionId::FORK, "fork" },
    { RopActionId::TELEFORK, "telefork" },
    { RopActionId::RET2USR, "ret2usr" },
};

std::vector<RopItem> Target::GetRopActionItems(RopActionId id) {
  std::string name = RopActionNames.at(id);
  if (rop_actions.find(name) == rop_actions.end())
    throw ExpKitError("missing RopActionID %u, name=%s", id, name.c_str());
  return rop_actions[name];
}

const std::string& Target::GetDistro() const {
  return distro;
}

const std::string& Target::GetReleaseName() const {
  return release_name;

}

const std::string& Target::GetVersion() const {
  return version;
}

uint32_t Target::GetSymbolOffset(std::string symbol_name) {
  auto it = symbols.find(symbol_name);
  if (it == symbols.end() || it->second == 0)
    throw ExpKitError("symbol (%s) is not available for the target",
                      symbol_name.c_str());
  return it->second;
}

Target::Target(const std::string& distro,
                           const std::string& release_name,
                           const std::string& version) {
  this->distro = distro;
  this->release_name = release_name;
  this->version = version;
}

void Target::AddSymbol(const std::string& name, uint64_t value) {
  symbols[name] = value;
}

void Target::AddStruct(const Struct& value) {
  structs[value.name] = value;
}

void Target::AddStruct(const std::string& name, uint64_t size,
                             const std::vector<StructField>& fields) {
  Struct str{name, size, {}};
  for (auto field : fields) str.fields[field.name] = field;
  structs[name] = str;
}

void Target::SetPivots(const Pivots& pivots) {
  this->pivots = pivots;
}

void Target::Merge(const Target& src) {
  if (!src.GetDistro().empty()) distro = src.GetDistro();
  if (!src.GetReleaseName().empty()) release_name = src.GetReleaseName();
  if (!src.GetVersion().empty()) version = src.GetVersion();

  symbols.insert(src.symbols.begin(), src.symbols.end());
  rop_actions.insert(src.rop_actions.begin(), src.rop_actions.end());

  pivots.one_gadgets.insert(pivots.one_gadgets.end(),
                                src.pivots.one_gadgets.begin(),
                                src.pivots.one_gadgets.end());
  pivots.push_indirects.insert(pivots.push_indirects.end(),
                                   src.pivots.push_indirects.begin(),
                                   src.pivots.push_indirects.end());
  pivots.pop_rsps.insert(pivots.pop_rsps.end(),
                             src.pivots.pop_rsps.begin(),
                             src.pivots.pop_rsps.end());
  pivots.stack_shifts.insert(pivots.stack_shifts.end(),
                                 src.pivots.stack_shifts.begin(),
                                 src.pivots.stack_shifts.end());

  for (const auto& [name, str] : src.structs) {
    if (structs.find(name) == structs.end()) {
      structs[name] = str;
    } else {
      structs[name].fields.insert(str.fields.begin(), str.fields.end());
    }
  }
}

const Pivots& Target::GetPivots() {
  return pivots;
}

std::map<std::string, uint32_t> Target::GetAllSymbols() {
  return symbols;
}

const Struct& Target::GetStruct(const std::string& name) {
  return structs[name];
}

void Target::AddRopAction(const std::string& name, std::vector<RopItem> value) {
  rop_actions[name] = value;
}

uint64_t Target::GetStructSize(const std::string& struct_name) {
  return GetStruct(struct_name).size;
}

uint64_t Target::GetFieldOffset(const std::string& struct_name, const std::string& field_name) {
  return GetStruct(struct_name).fields.at(field_name).offset;
}

uint64_t Target::GetFieldSize(const std::string& struct_name, const std::string& field_name) {
  return GetStruct(struct_name).fields.at(field_name).size;
}
