#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <vector>
#include "target/BinaryReader.cpp"
#include "target/Target.cpp"
#include "pivot/Pivots.cpp"
#include "util/error.cpp"
#include "util/file.cpp"

class KpwnParser: protected BinaryReader {
protected:
    uint32_t num_targets_;
    std::vector<SymbolId> symbol_ids_;
    std::vector<RopActionId> rop_action_ids_;

    void ParseSymbolsHeader() {
        auto num_symbols = ReadU32();
        DebugLog("num_symbols = %d", num_symbols);
        for (int i = 0; i < num_symbols; i++, EndStruct()) {
            BeginStruct(2);
            auto type_id = ReadU32();
            DebugLog("symbol[%d] = %x", i, type_id);
            symbol_ids_.push_back((SymbolId) type_id);
        }
    }

    void ParseSymbols(Target& target) {
        DebugLog("ParseSymbols (num=%u)", symbol_ids_.size());
        for (auto type_id : symbol_ids_) {
            target.symbols[type_id] = ReadU32();
            DebugLog("symbol[0x%x] = 0x%x", type_id, target.symbols[type_id]);
        }
    }

    void ParseRopActionsHeader(bool parse_known_metadata) {
        auto num_rop_actions = ReadU32();
        DebugLog("num_rop_actions = %d", num_rop_actions);
        for (int i = 0; i < num_rop_actions; i++, EndStruct()) {
            BeginStruct(2);
            auto type_id = (RopActionId) ReadU32();
            rop_action_ids_.push_back(type_id);
            if (parse_known_metadata) {
                auto desc = ZStr(ReadU16());
                auto num_args = ReadU8();
                DebugLog("rop_action[%d] = %d, num_args = %d, desc = '%s'", i, type_id, num_args, desc);

                RopActionMeta ra(type_id, desc);
                for (int j = 0; j < num_args; j++) {
                    auto arg_name = ZStr(ReadU16());
                    auto flags = ReadU8();
                    bool required = (flags & 0x1) == 0x1;
                    uint64_t default_value = required ? 0 : ReadU64();
                    DebugLog("argument: name='%s', flags=0x%x, default_value=%x", arg_name, flags, default_value);
                    ra.args.push_back(RopActionArgMeta(arg_name, required, default_value));
                }
                rop_action_meta_.insert({type_id, ra});
            }
        }
    }

    void ParseRopActions(Target& target) {
        DebugLog("ParseRopActions (num=%u)", rop_action_ids_.size());
        for (int i_action = 0; i_action < rop_action_ids_.size(); i_action++, EndStruct()) {
            // skip if this ROP action is not supported
            if (!BeginStruct(2)) continue;

            auto num_items = ReadUInt();
            std::vector<RopItem> rop_items;
            for (int i = 0; i < num_items; i++) {
                auto type_and_value = ReadUInt();
                rop_items.push_back(RopItem((RopItemType)(type_and_value & 0x03), type_and_value >> 2));
            }

            auto type_id = rop_action_ids_[i_action];
            target.rop_actions[type_id] = rop_items;
        }
    }

    RegisterUsage ReadRegisterUsage() {
        RegisterUsage reg_usage;
        reg_usage.reg = (Register) ReadUInt();
        auto count = ReadUInt();
        for (int i = 0; i < count; i++)
            reg_usage.used_offsets.push_back(ReadInt());
        return reg_usage;
    }

    void ParsePivots(Target& target) {
        DebugLog("ParsePivots()");
        if (!BeginStruct(2, false))
            return;

        auto num_one_gadgets = ReadUInt();
        DebugLog("ParsePivots(): num_one_gadgets = %u", num_one_gadgets);
        for (int i = 0; i < num_one_gadgets; i++) {
            OneGadgetPivot pivot;
            pivot.address = ReadUInt();
            pivot.pivot_reg = ReadRegisterUsage();
            pivot.next_rip_offset = ReadInt();
            target.pivots.one_gadgets.push_back(pivot);
            DebugLog("one_gadgets[%u]: address=0x%x, pivot_reg=%u, next_rip_offset=%d", i, pivot.address, pivot.pivot_reg.reg, pivot.next_rip_offset);
        }

        auto num_push_indirects = ReadUInt();
        DebugLog("ParsePivots(): num_push_indirects = %u", num_push_indirects);
        for (int i = 0; i < num_push_indirects; i++) {
            PushIndirectPivot pivot;
            pivot.address = ReadUInt();
            pivot.indirect_type = (IndirectType) ReadUInt();
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

        EndStruct();
    }

    Target ParseTarget(std::optional<const std::string> distro, std::optional<const std::string> release_name, std::optional<const std::string> version) {
        if (offset_targets_ == 0)
            ParseHeader();

        offset_ = offset_targets_;
        DebugLog("ParseTarget(): offset = 0x%x", offset_targets_);
        for (uint32_t i_target = 0; i_target < num_targets_; i_target++, EndStruct()) {
            BeginStruct(4);

            auto distro_len = ReadU16();
            const char* t_distro = ZStr(distro_len);

            auto release_name_len = ReadU16();
            const char* t_release = ZStr(release_name_len);

            auto version_len = ReadU16();
            const char* t_version = ZStr(version_len);

            DebugLog("target[%d] distro_len = %d, release_name_len = %d, version_len = %d", i_target, distro_len, release_name_len, version_len);
            if ((distro.has_value() && distro_len != distro->length()) ||
                (release_name.has_value() && release_name_len != release_name->length()) ||
                (version.has_value() && version_len != version->length()))
                continue;

            DebugLog("distro = '%s', release = '%s', version = '%s'", t_distro, t_release, t_version);
            if ((distro.has_value() && strcmp(distro->c_str(), t_distro)) ||
                (release_name.has_value() && strcmp(release_name->c_str(), t_release)) ||
                (version.has_value() && strcmp(version->c_str(), t_version)))
                continue;

            Target result;
            result.distro = t_distro;
            result.release_name = t_release;
            result.version = t_version;

            ParseSymbols(result);
            ParseRopActions(result);
            ParsePivots(result);
            return result;
        }

        if (version.has_value())
            throw ExpKitError("target was not found for version: %s", version->c_str());
        else
            throw ExpKitError("target was not found for release: %s/%s", distro->c_str(), release_name->c_str());
    }

public:
    std::map<RopActionId, RopActionMeta> rop_action_meta_;

    KpwnParser(const uint8_t* buffer, size_t size): BinaryReader(buffer, size) {
    }

    KpwnParser(const std::vector<uint8_t> data): BinaryReader(data.data(), data.size()) {
    }

    static KpwnParser FromFile(const char* filename) {
        return KpwnParser(read_file(filename));
    }

    void SetLog(ILog* log) {
        log_ = log;
    }

    void ParseHeader(bool parse_known_metadata = false) {
        if (offset_ != 0)
            throw ExpKitError("header can only be parsed from offset 0, current offset is 0x%llx", offset_);

        auto magic = ReadU32();
        if (magic != *(uint32_t*)"KPWN")
            throw ExpKitError("invalid magic: %llx", magic);

        auto version_major = ReadU16();
        auto version_minor = ReadU16();
        if (version_major > 1)
            throw ExpKitError("version v%d.%d is not supported (only v1.x)", version_major, version_minor);

        BeginStruct(4); // meta header
        ParseSymbolsHeader();
        ParseRopActionsHeader(parse_known_metadata);
        EndStruct();

        num_targets_ = ReadU32();
        offset_targets_ = offset_;
    }

    Target GetTarget(const std::string& distro, const std::string& release_name) {
        return ParseTarget(distro, release_name, std::nullopt);
    }

    Target GetTarget(const std::string& version) {
        return ParseTarget(std::nullopt, std::nullopt, version);
    }

    Target AutoDetectTarget() {
        auto version_bytes = read_file("/proc/version");
        std::string version(version_bytes.begin(), version_bytes.end() - 1);
        return GetTarget(version);
    }
};