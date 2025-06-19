#pragma once

#include "target/KpwnParser.hpp"
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <vector>
#include "target/Target.hpp"
#include "pivot/Pivots.cpp"
#include "util/error.cpp"
#include "util/file.cpp"

std::vector<Target> KpwnParser::GetAllTargets() {
  return ParseTargets(std::nullopt, std::nullopt, std::nullopt);
}

std::optional<Target> KpwnParser::GetTarget(const std::string& version,
                                            bool throw_on_missing) {
  return ParseTarget(std::nullopt, std::nullopt, version, throw_on_missing);
}

std::optional<Target> KpwnParser::GetTarget(const std::string& distro,
                                            const std::string& release_name,
                                            bool throw_on_missing) {
  return ParseTarget(distro, release_name, std::nullopt, throw_on_missing);
}

void KpwnParser::ParseHeader(bool parse_known_metadata) {
  if (offset_ != 0)
    throw ExpKitError(
        "header can only be parsed from offset 0, current offset is 0x%llx",
        offset_);

  auto magic = ReadU32();
  if (magic != *(uint32_t*)"KPWN")
    throw ExpKitError("invalid magic: %llx", magic);

  auto version_major = ReadU16();
  auto version_minor = ReadU16();
  if (version_major > 1)
    throw ExpKitError("version v%d.%d is not supported (only v1.x)",
                      version_major, version_minor);

  has_structs_data_ = version_minor >= 1;

  BeginStruct(4);  // meta header
  ParseSymbolsHeader();
  ParseRopActionsHeader(parse_known_metadata);
  ParseStructsHeader();
  EndStruct();

  num_targets_ = ReadU32();
  offset_targets_ = offset_;
}

void KpwnParser::SetLog(ILog* log) { log_ = log; }

KpwnParser KpwnParser::FromFile(const char* filename) {
  return KpwnParser(read_file(filename));
}

KpwnParser::KpwnParser(const std::vector<uint8_t> data)
    : BinaryReader(data.data(), data.size()) {}

KpwnParser::KpwnParser(const uint8_t* buffer, size_t size)
    : BinaryReader(buffer, size) {}

std::optional<Target> KpwnParser::ParseTarget(
    std::optional<const std::string> distro,
    std::optional<const std::string> release_name,
    std::optional<const std::string> version, bool throw_on_missing) {
  auto targets = ParseTargets(distro, release_name, version);

  if (targets.size() == 1) return targets[0];

  if (targets.size() == 0 && !throw_on_missing) return std::nullopt;

  auto error = targets.size() > 1 ? "multiple targets were found"
                                  : "target was not found";
  if (version.has_value())
    throw ExpKitError("%s for version: %s", error, version->c_str());
  else
    throw ExpKitError("%s for release: %s/%s", error, distro->c_str(),
                      release_name->c_str());
}

std::vector<Target> KpwnParser::ParseTargets(
    std::optional<const std::string> distro,
    std::optional<const std::string> release_name,
    std::optional<const std::string> version) {
  if (offset_targets_ == 0) ParseHeader();

  std::vector<Target> result;
  offset_ = offset_targets_;
  DebugLog("ParseTarget(): offset = 0x%x", offset_targets_);
  for (uint32_t i_target = 0; i_target < num_targets_;
       i_target++, EndStruct()) {
    BeginStruct(4);

    auto distro_len = ReadU16();
    const char* t_distro = ZStr(distro_len);

    auto release_name_len = ReadU16();
    const char* t_release = ZStr(release_name_len);

    auto version_len = ReadU16();
    const char* t_version = ZStr(version_len);

    DebugLog(
        "target[%d] distro_len = %d, release_name_len = %d, version_len = %d",
        i_target, distro_len, release_name_len, version_len);
    if ((distro.has_value() && distro_len != distro->length()) ||
        (release_name.has_value() &&
         release_name_len != release_name->length()) ||
        (version.has_value() && version_len != version->length()))
      continue;

    DebugLog("distro = '%s', release = '%s', version = '%s'", t_distro,
             t_release, t_version);
    if ((distro.has_value() && strcmp(distro->c_str(), t_distro)) ||
        (release_name.has_value() &&
         strcmp(release_name->c_str(), t_release)) ||
        (version.has_value() && strcmp(version->c_str(), t_version)))
      continue;

    Target target;
    target.distro = t_distro;
    target.release_name = t_release;
    target.version = t_version;

    ParseSymbols(target);
    ParseRopActions(target);
    ParsePivots(target);
    ParseStructs(target);
    result.push_back(target);
  }

  return result;
}

void KpwnParser::ParseStructs(Target& target) {
  if (!has_structs_data_) return;
  DebugLog("ParseStructs(): count=%u", structs_meta_.size());

  for (int i = 0; i < structs_meta_.size(); i++) {
    // layout_idx_opt = layout_idx + 1 or 0 if the struct does not exist in this
    // release
    auto layout_idx_opt = ReadUInt();
    DebugLog("  struct[%u]: layout_idx_opt=%u", i, layout_idx_opt);
    if (layout_idx_opt == 0) continue;
    auto str = GetStructLayout(layout_idx_opt - 1);
    target.structs[str.name] = str;
  }
}

Struct& KpwnParser::GetStructLayout(uint64_t layout_idx) {
  auto str = struct_layouts_.find(layout_idx);
  if (str != struct_layouts_.end()) return str->second;
  return ParseStructLayout(layout_idx);
}

Struct& KpwnParser::ParseStructLayout(uint64_t layout_idx) {
  DebugLog("ParseStructLayout(): layout_idx=%u", layout_idx);
  SeekToItem(offset_struct_layouts_, layout_idx);

  auto meta_idx = ReadUInt();
  auto [struct_name, fields] = structs_meta_.at(meta_idx);

  Struct str;
  str.size = ReadUInt();
  str.name = struct_name;
  for (auto& field_meta : fields) {
    auto offset = ReadUInt();
    if (offset == 0) {
      if (!field_meta.optional)
        throw ExpKitError("Non-optional field is missing: %s",
                          field_meta.field_name.c_str());
      continue;
    }

    StructField field;
    field.name = field_meta.field_name;
    field.offset = offset - 1;
    field.size = ReadUInt();
    str.fields[field_meta.field_name] = field;
  }
  EndSeek();

  struct_layouts_[layout_idx] = str;
  return struct_layouts_[layout_idx];
}

void KpwnParser::ParseStructsHeader() {
  if (!has_structs_data_) return;
  DebugLog("ParseStructsHeader()");

  auto num_structs = ReadUInt();
  DebugLog("ParseStructsHeader(): num_structs=%u", num_structs);

  for (int i = 0; i < num_structs; i++) {
    auto struct_name = ZStr();
    auto num_fields = ReadUInt();
    DebugLog("  struct[%u]: name:%s field_count:%u", i, struct_name,
             num_fields);

    std::vector<FieldMeta> fields;
    for (int j = 0; j < num_fields; j++) {
      auto field_name = ZStr();
      auto optional = ReadU8() == 1;
      fields.push_back({field_name, optional});
    }

    structs_meta_.push_back({struct_name, fields});
  }
  offset_struct_layouts_ = ReadU32();
}

void KpwnParser::ParsePivots(Target& target) {
  DebugLog("ParsePivots()");
  if (!BeginStruct(2, false)) return;

  auto num_one_gadgets = ReadUInt();
  DebugLog("ParsePivots(): num_one_gadgets = %u", num_one_gadgets);
  for (int i = 0; i < num_one_gadgets; i++) {
    OneGadgetPivot pivot;
    pivot.address = ReadUInt();
    pivot.pivot_reg = ReadRegisterUsage();
    pivot.next_rip_offset = ReadInt();
    target.pivots.one_gadgets.push_back(pivot);
    DebugLog("one_gadgets[%u]: address=0x%x, pivot_reg=%u, next_rip_offset=%d",
             i, pivot.address, pivot.pivot_reg.reg, pivot.next_rip_offset);
  }

  auto num_push_indirects = ReadUInt();
  DebugLog("ParsePivots(): num_push_indirects = %u", num_push_indirects);
  for (int i = 0; i < num_push_indirects; i++) {
    PushIndirectPivot pivot;
    pivot.address = ReadUInt();
    pivot.indirect_type = (IndirectType)ReadUInt();
    pivot.push_reg = ReadRegisterUsage();
    pivot.indirect_reg = ReadRegisterUsage();
    pivot.next_rip_offset = ReadInt();
    target.pivots.push_indirects.push_back(pivot);
  }

  auto num_poprsps = ReadUInt();
  DebugLog("ParsePivots(): num_poprsps = %u", num_poprsps);
  for (int i = 0; i < num_poprsps; i++) {
    PopRspPivot pivot;
    pivot.address = ReadUInt();
    pivot.stack_change_before_rsp = ReadInt();
    pivot.next_rip_offset = ReadInt();
    target.pivots.pop_rsps.push_back(pivot);
  }

  auto num_stack_shifts = ReadUInt();
  DebugLog("ParsePivots(): num_stack_shifts = %u", num_stack_shifts);
  for (int i = 0; i < num_stack_shifts; i++) {
    StackShiftPivot pivot;
    pivot.address = ReadUInt();
    pivot.ret_offset = ReadUInt();
    pivot.shift_amount = ReadUInt();
    target.pivots.stack_shifts.push_back(pivot);
    DebugLog("stack_shift[%u]: address=0x%x, ret_offset=%u, shift_amount=%d", i,
             pivot.address, pivot.ret_offset, pivot.shift_amount);
  }

  EndStruct();
}

RegisterUsage KpwnParser::ReadRegisterUsage() {
  RegisterUsage reg_usage;
  reg_usage.reg = (Register)ReadUInt();
  auto count = ReadUInt();
  for (int i = 0; i < count; i++) reg_usage.used_offsets.push_back(ReadInt());
  return reg_usage;
}

void KpwnParser::ParseRopActions(Target& target) {
  DebugLog("ParseRopActions (num=%u)", rop_action_ids_.size());
  for (int i_action = 0; i_action < rop_action_ids_.size();
       i_action++, EndStruct()) {
    // skip if this ROP action is not supported
    if (!BeginStruct(2)) continue;

    auto num_items = ReadUInt();
    std::vector<RopItem> rop_items;
    for (int i = 0; i < num_items; i++) {
      auto type_and_value = ReadUInt();
      rop_items.push_back(
          RopItem((RopItemType)(type_and_value & 0x03), type_and_value >> 2));
    }

    auto type_id = rop_action_ids_[i_action];
    target.rop_actions[type_id] = rop_items;
  }
}

void KpwnParser::ParseRopActionsHeader(bool parse_known_metadata) {
  auto num_rop_actions = ReadU32();
  DebugLog("num_rop_actions = %d", num_rop_actions);
  for (int i = 0; i < num_rop_actions; i++, EndStruct()) {
    BeginStruct(2);
    auto type_id = (RopActionId)ReadU32();
    rop_action_ids_.push_back(type_id);
    if (parse_known_metadata) {
      auto desc = ZStr(ReadU16());
      auto num_args = ReadU8();
      DebugLog("rop_action[%d] = %d, num_args = %d, desc = '%s'", i, type_id,
               num_args, desc);

      RopActionMeta ra(type_id, desc);
      for (int j = 0; j < num_args; j++) {
        auto arg_name = ZStr(ReadU16());
        auto flags = ReadU8();
        bool required = (flags & 0x1) == 0x1;
        uint64_t default_value = required ? 0 : ReadU64();
        DebugLog("argument: name='%s', flags=0x%x, default_value=%x", arg_name,
                 flags, default_value);
        ra.args.push_back(RopActionArgMeta(arg_name, required, default_value));
      }
      rop_action_meta_.insert({type_id, ra});
    }
  }
}

void KpwnParser::ParseSymbols(Target& target) {
  DebugLog("ParseSymbols (num=%u)", symbol_names_.size());
  for (auto& name : symbol_names_) {
    auto value = ReadU32();
    target.symbols[name] = value;
    DebugLog("symbol[%s] = 0x%x", name.c_str(), value);
  }
}

void KpwnParser::ParseSymbolsHeader() {
  auto num_symbols = ReadU32();
  DebugLog("num_symbols = %d", num_symbols);
  for (int i = 0; i < num_symbols; i++, EndStruct()) {
    BeginStruct(2);
    auto type_id = ReadU32();
    auto name_len = ReadU16();
    auto name = ZStr(name_len);
    DebugLog("symbol[%d] = %s", i, name);
    symbol_names_.push_back(name);
  }
}
