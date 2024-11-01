#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <vector>
#include "target/Target.cpp"
#include "util/error.cpp"
#include "util/file.cpp"
#include "util/log.cpp"

class KpwnParser {
protected:
    std::vector<uint8_t> data_;
    uint64_t offset_ = 0, offset_targets_ = 0;
    std::vector<uint64_t> struct_ends_;
    uint32_t num_targets_;
    std::vector<SymbolId> symbol_ids_;
    std::vector<RopActionId> rop_action_ids;
    ILog* log_ = nullptr;

    uint64_t Uint(int size) {
        if (size == 1) return ReadU8();
        else if (size == 2) return ReadU16();
        else if (size == 4) return ReadU32();
        else if (size == 8) return ReadU64();
        else
            throw ExpKitError("unsupported uint size (%d)", size);
    }

    uint64_t RemainingBytes() {
        return struct_ends_.back() - offset_;
    }

    void SizeCheck(uint64_t len) {
        if (RemainingBytes() < len)
            throw ExpKitError("tried to read outside of buffer: offset=%u, len=%u, struct_end=%u", offset_, len, struct_ends_.back());
    }

    uint8_t* Read(uint16_t len) {
        SizeCheck(len);
        uint8_t* ptr = &data_.data()[offset_];
        offset_ += len;
        return ptr;
    }

    uint8_t ReadU8() {
        return *(uint8_t*)Read(1);
    }

    uint16_t ReadU16() {
        return *(uint16_t*)Read(2);
    }

    uint32_t ReadU32() {
        return *(uint32_t*)Read(4);
    }

    uint64_t ReadU64() {
        return *(uint64_t*)Read(8);
    }

    template <typename... Args>
    inline void DebugLog(const char* format, const Args&... args) {
        if (log_)
            log_->log(LogLevel::DEBUG, "%s\t[offs=%u]", format_str(format, args...).c_str(), offset_);
    }

    bool BeginStruct(int struct_size_len) {
        if (struct_size_len != 2 && struct_size_len != 4)
            throw ExpKitError("unsupported struct_size_len (%d), only 2 and 4 supported", struct_size_len);

        auto struct_size = struct_size_len == 2 ? ReadU16() : ReadU32();
        DebugLog("BeginStruct(): offset = %u, struct_size = %u, end_offset = %u", offset_, struct_size, offset_ + struct_size);
        SizeCheck(struct_size);
        struct_ends_.push_back(offset_ + struct_size);
        return struct_size > 0;
    }

    void EndStruct() {
        if (struct_ends_.empty())
            throw ExpKitError("cannot call EndStruct() if BeginStruct() was not called before");
        offset_ = struct_ends_.back();
        struct_ends_.pop_back();
    }

    const char* ZStr(uint16_t len) {
        return (char*) Read(len + 1);
    }

    Target ParseTarget(std::optional<const std::string> distro, std::optional<const std::string> release_name, std::optional<const std::string> version) {
        if (offset_targets_ == 0)
            ParseHeader();

        offset_ = offset_targets_;
        DebugLog("offset = 0x%x", offset_targets_);
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

            DebugLog("distro = %s, release = %s, version = '%s'", t_distro, t_release, t_version);
            if ((distro.has_value() && strcmp(distro->c_str(), t_distro)) ||
                (release_name.has_value() && strcmp(release_name->c_str(), t_release)) ||
                (version.has_value() && strcmp(version->c_str(), t_version)))
                continue;

            Target result;
            result.distro = t_distro;
            result.release_name = t_release;
            result.version = t_version;
            for (auto type_id : symbol_ids_) {
                result.symbols[type_id] = ReadU32();
                DebugLog("symbol[0x%x] = 0x%x", type_id, result.symbols[type_id]);
            }

            for (int i_action = 0; i_action < rop_action_ids.size(); i_action++, EndStruct()) {
                // skip if this ROP action is not supported
                if (!BeginStruct(2)) continue;

                auto num_items = ReadU8();
                std::vector<RopItem> rop_items;
                for (int i = 0; i < num_items; i++) {
                    auto type_and_size = ReadU8();
                    auto type = (RopItemType)(type_and_size >> 4);
                    auto size = type_and_size & 0xf;
                    auto read_size = 1 << size;
                    uint64_t value = Uint(read_size);
                    rop_items.push_back(RopItem(type, value));
                }

                auto type_id = rop_action_ids[i_action];
                result.rop_actions[type_id] = rop_items;
            }

            return result;
        }

        if (version.has_value())
            throw ExpKitError("target was not found for version: %s", version->c_str());
        else
            throw ExpKitError("target was not found for release: %s/%s", distro->c_str(), release_name->c_str());
    }

public:
    std::map<RopActionId, RopActionMeta> rop_action_meta_;

    KpwnParser(const uint8_t* buffer, size_t size): data_(buffer, buffer + size) {
        struct_ends_.push_back(size);
    }

    KpwnParser(const std::vector<uint8_t> data): KpwnParser(data.data(), data.size()) {
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

        BeginStruct(4);

        auto num_symbols = ReadU32();
        DebugLog("num_symbols = %d", num_symbols);
        for (int i = 0; i < num_symbols; i++, EndStruct()) {
            BeginStruct(2);
            auto type_id = ReadU32();
            DebugLog("symbol[%d] = %x", i, type_id);
            symbol_ids_.push_back((SymbolId) type_id);
        }

        auto num_rop_actions = ReadU32();
        DebugLog("num_rop_actions = %d", num_rop_actions);
        for (int i = 0; i < num_rop_actions; i++, EndStruct()) {
            BeginStruct(2);
            auto type_id = (RopActionId) ReadU32();
            rop_action_ids.push_back(type_id);
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
        std::string version(version_bytes.begin(), version_bytes.end());
        return GetTarget(version);
    }
};