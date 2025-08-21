#include "target/KxdbParser.h"
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <vector>
#include <kernelXDK/target/Target.h>
#include <kernelXDK/pivot/Pivots.h>
#include <kernelXDK/util/error.h>
#include "util/file.h"

std::vector<Target> KxdbParser::GetAllTargets() {
  return ParseTargets(std::nullopt, std::nullopt, std::nullopt);
}

std::optional<Target> KxdbParser::GetTarget(const std::string& version,
                                            bool throw_on_missing) {
  return ParseTarget(std::nullopt, std::nullopt, version, throw_on_missing);
}

std::optional<Target> KxdbParser::GetTarget(const std::string& distro,
                                            const std::string& release_name,
                                            bool throw_on_missing) {
  return ParseTarget(distro, release_name, std::nullopt, throw_on_missing);
}

void KxdbParser::ParseHeader() {
  if (offset_ != 0)
    throw ExpKitError(
        "header can only be parsed from offset 0, current offset is 0x%llx",
        offset_);

  auto magic = ReadU32();
  // TODO remove KPWN magic check after db rebuild
  if (magic != *(uint32_t*)"KXDB")
    throw ExpKitError("invalid magic: %llx", magic);

  auto version_major = ReadU16();
  auto version_minor = ReadU16();
  if (version_major > 1)
    throw ExpKitError("version v%d.%d is not supported (only v1.x)",
                      version_major, version_minor);

  auto num_sections = ReadU16();
  for (auto i = 0; i < num_sections; i++) {
    auto id = ReadU16();
    sections_[(Section) id] = { .offset = ReadU32(), .size = ReadU32() };
  }

  ParseSymbolsHeader();
  ParseRopActionsHeader();
  ParseStructsHeader();

  offset_targets_ = offset_;
  offset_struct_layouts_ = sections_[Section::StructLayouts].offset;
}

void KxdbParser::SetLog(ILog* log) { log_ = log; }

KxdbParser KxdbParser::FromFile(const std::string &filename) {
  return KxdbParser(read_file(filename));
}

KxdbParser::KxdbParser(const std::vector<uint8_t> data)
    : BinaryReader(data.data(), data.size()) {}

KxdbParser::KxdbParser(const uint8_t* buffer, size_t size)
    : BinaryReader(buffer, size) {}

std::optional<Target> KxdbParser::ParseTarget(
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

std::vector<Target> KxdbParser::ParseTargets(
    std::optional<const std::string> distro,
    std::optional<const std::string> release_name,
    std::optional<const std::string> version) {
  if (offset_targets_ == 0) ParseHeader();

  std::vector<Target> result;
  offset_ = offset_targets_;
  auto by_version = SeekableListCount();
  auto num_targets = SeekableListCount();
  DebugLog("ParseTarget(): offset = 0x%x, by_version=%u, num_targets=%u", offset_targets_, by_version, num_targets);
  for (uint32_t i_target = 0; i_target < num_targets;
       i_target++) {
    const char* t_distro = ZStr();
    const char* t_release = ZStr();
    const char* t_version = ZStr();

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

void KxdbParser::ParseStructs(Target& target) {
  DebugLog("ParseStructs(): count=%u", structs_meta_.size());
  for (size_t i = 0; i < structs_meta_.size(); i++) {
    // layout_idx_opt = layout_idx + 1 or 0 if the struct does not exist in this
    // release
    auto layout_idx_opt = ReadUInt();
    DebugLog("  struct[%u]: layout_idx_opt=%u", i, layout_idx_opt);
    if (layout_idx_opt == 0) continue;
    auto str = GetStructLayout(layout_idx_opt - 1);
    target.structs[str.name] = str;
  }
}

Struct& KxdbParser::GetStructLayout(uint64_t layout_idx) {
  auto str = struct_layouts_.find(layout_idx);
  if (str != struct_layouts_.end()) return str->second;
  return ParseStructLayout(layout_idx);
}

Struct& KxdbParser::ParseStructLayout(uint64_t layout_idx) {
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

void KxdbParser::ParseStructsHeader() {
  DebugLog("ParseStructsHeader()");

  auto num_structs = SeekableListCount();
  DebugLog("ParseStructsHeader(): num_structs=%u", num_structs);

  for (uint64_t i = 0; i < num_structs; i++) {
    auto struct_name = ZStr();
    auto num_fields = ReadUInt();
    DebugLog("  struct[%u]: name:%s field_count:%u", i, struct_name,
             num_fields);

    std::vector<FieldMeta> fields;
    for (uint64_t j = 0; j < num_fields; j++) {
      auto field_name = ZStr();
      auto optional = ReadU8() == 1;
      fields.push_back({field_name, optional});
    }

    structs_meta_.push_back({struct_name, fields});
  }
}

void KxdbParser::ParsePivots(Target& target) {
  BeginStruct(-1);

  auto num_one_gadgets = ReadUInt();
  DebugLog("ParsePivots(): num_one_gadgets = %u", num_one_gadgets);
  for (uint64_t i = 0; i < num_one_gadgets; i++) {
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
  for (uint64_t i = 0; i < num_push_indirects; i++) {
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
  for (uint64_t i = 0; i < num_poprsps; i++) {
    PopRspPivot pivot;
    pivot.address = ReadUInt();
    pivot.stack_change_before_rsp = ReadInt();
    pivot.next_rip_offset = ReadInt();
    target.pivots.pop_rsps.push_back(pivot);
  }

  auto num_stack_shifts = ReadUInt();
  DebugLog("ParsePivots(): num_stack_shifts = %u", num_stack_shifts);
  for (uint64_t i = 0; i < num_stack_shifts; i++) {
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

RegisterUsage KxdbParser::ReadRegisterUsage() {
  RegisterUsage reg_usage;
  reg_usage.reg = (Register)ReadUInt();
  auto count = ReadUInt();
  for (uint64_t i = 0; i < count; i++)
    reg_usage.used_offsets.push_back(ReadInt());
  return reg_usage;
}

void KxdbParser::ParseRopActions(Target& target) {
  auto sizes = SeekableListSizes();
  DebugLog("ParseRopActions (num=%u == %u)", rop_action_meta_.size(), sizes.size());
  for (size_t i_action = 0; i_action < rop_action_meta_.size(); i_action++) {
    if (sizes[i_action] == 0) continue;

    auto name = split(rop_action_meta_[i_action].desc, "(")[0];
    auto num_items = ReadUInt();
    DebugLog("  RA[%s] num_items = %u", name.c_str(), num_items);
    std::vector<RopItem> rop_items;
    for (uint64_t i = 0; i < num_items; i++) {
      auto type_and_value = ReadUInt();
      auto type = (RopItemType)(type_and_value & 0x03);
      auto value = type_and_value >> 2;
      DebugLog("  RA[%s] item[%u] type = %u, value = %u", name.c_str(), i, type, value);
      rop_items.push_back(RopItem(type, value));
    }

    target.rop_actions[name] = rop_items;
  }
}

void KxdbParser::ParseRopActionsHeader() {
  auto num_rop_actions = SeekableListCount();
  DebugLog("num_rop_actions = %d", num_rop_actions);
  for (uint64_t i = 0; i < num_rop_actions; i++) {
    auto desc = ZStr();
    auto num_args = ReadUInt();
    DebugLog("rop_action[%d], num_args = %d, desc = '%s'", i, num_args, desc);

    RopActionMeta ra(desc);
    for (int j = 0; j < num_args; j++) {
      auto arg_name = ZStr();
      auto flags = ReadU8();
      bool required = (flags & 0x1) == 0x1;
      uint64_t default_value = required ? 0 : ReadUInt();
      DebugLog("  argument: name='%s', flags=0x%x, default_value=%x", arg_name,
               flags, default_value);
      ra.args.push_back(RopActionArgMeta(arg_name, required, default_value));
    }
    rop_action_meta_.push_back(ra);
  }
}

void KxdbParser::ParseSymbols(Target& target) {
  DebugLog("ParseSymbols (num=%u)", symbol_names_.size());
  for (auto& name : symbol_names_) {
    auto value = ReadU32();
    target.symbols[name] = value;
    DebugLog("  symbol[%s] = 0x%x", name.c_str(), value);
  }
}

void KxdbParser::ParseSymbolsHeader() {
  auto num_symbols = SeekableListCount();
  DebugLog("num_symbols = %d", num_symbols);
  for (uint64_t i = 0; i < num_symbols; i++) {
    auto name = ZStr();
    DebugLog("symbol[%d] = %s", i, name);
    symbol_names_.push_back(name);
  }
}
