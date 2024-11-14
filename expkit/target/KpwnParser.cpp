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
    ILog* log_ = nullptr;


    uint64_t Uint(int size) {
        if (size == 1) return ReadU8();
        else if (size == 2) return ReadU16();
        else if (size == 4) return ReadU32();
        else if (size == 8) return ReadU64();
        else
            throw ExpKitError("unsupported uint size (%d)", size);
    }

    void SizeCheck(uint64_t len) {
        if (data_.size() - offset_ < len)
            throw ExpKitError("tried to read outside of buffer: offset=%u, len=%u, db_size=%u", offset_, len, data_.size());
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
            log_->log(LogLevel::DEBUG, format, args...);
    }

    void BeginStruct(int struct_size_len) {
        if (struct_size_len != 2 && struct_size_len != 4)
            throw ExpKitError("unsupported struct_size_len (%d), only 2 and 4 supported", struct_size_len);

        auto struct_size = struct_size_len == 2 ? ReadU16() : ReadU32();
        DebugLog("struct_size = %u", struct_size);
        SizeCheck(struct_size_len);
        struct_ends_.push_back(offset_ + struct_size);
    }

    void EndStruct() {
        if (struct_ends_.empty())
            throw ExpKitError("cannot call end_struct() if begin_struct was not called before");
        offset_ = struct_ends_.back();
        struct_ends_.pop_back();
    }

    void ParseHeader() {
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
        for (uint32_t i = 0; i < num_symbols; i++, EndStruct()) {
            BeginStruct(2);
            auto type_id = ReadU32();
            DebugLog("symbol[%d] = %x", i, type_id);
            symbol_ids_.push_back((SymbolId) type_id);
        }

        EndStruct();

        num_targets_ = ReadU32();
        offset_targets_ = offset_;
    }

    const char* ZStr(uint16_t len) {
        return (char*) Read(len + 1);
    }

    Target ParseTarget(std::optional<const std::string> distro, std::optional<const std::string> release_name, std::optional<const std::string> version) {
        if (offset_ == 0)
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

            DebugLog("target[%d] struct_size = %d, distro_len = %d, release_name_len = %d, version_len = %d", i_target, struct_ends_.back() - offset_, distro_len, release_name_len, version_len);
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

            return result;
        }

        if (version.has_value())
            throw ExpKitError("target was not found for version: %s", version->c_str());
        else
            throw ExpKitError("target was not found for release: %s/%s", distro->c_str(), release_name->c_str());
    }

public:
    KpwnParser(const std::vector<uint8_t> data): data_(data) {
    }

    KpwnParser(const char* buffer, size_t size): data_(size) {
        std::memcpy(data_.data(), buffer, size);
    }

    static KpwnParser FromFile(const char* filename) {
        return KpwnParser(read_file(filename));
    }

    void SetLog(ILog* log) {
        log_ = log;
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