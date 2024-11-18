#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include "util/error.cpp"
#include "util/file.cpp"
#include "util/log.cpp"

class BinaryReader {
protected:
    std::vector<uint8_t> data_;
    uint64_t offset_ = 0, offset_targets_ = 0;
    std::vector<uint64_t> struct_ends_;
    ILog* log_ = nullptr;
    uint log_padding = 0;

public:
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
        static const char spaces[] = "                                                                     ";
        if (log_) {
            auto str = format_str(format, args...);
            log_->log(LogLevel::DEBUG, "%.*s%s%.*s[offs=%u]", log_padding, spaces, str.c_str(), 80 - log_padding - str.size(), spaces, offset_);
        }
    }

    bool BeginStruct(int struct_size_len, bool begin_if_empty = true) {
        if (struct_size_len != 2 && struct_size_len != 4)
            throw ExpKitError("unsupported struct_size_len (%d), only 2 and 4 supported", struct_size_len);

        auto struct_size = struct_size_len == 2 ? ReadU16() : ReadU32();
        DebugLog("BeginStruct(): offset = %u, struct_size = %u, end_offset = %u", offset_, struct_size, offset_ + struct_size);
        SizeCheck(struct_size);
        bool empty = struct_size == 0;
        if (!empty || begin_if_empty) {
            struct_ends_.push_back(offset_ + struct_size);
            log_padding += 2;
        }
        return !empty;
    }

    void EndStruct() {
        if (struct_ends_.empty())
            throw ExpKitError("cannot call EndStruct() if BeginStruct() was not called before");
        DebugLog("EndStruct(): jumping to offset %u (not parsed bytes in struct: %u)", struct_ends_.back(), RemainingBytes());
        offset_ = struct_ends_.back();
        struct_ends_.pop_back();
        log_padding -= 2;
    }

    const char* ZStr(uint16_t len) {
        return (char*) Read(len + 1);
    }

    BinaryReader(const uint8_t* buffer, size_t size): data_(buffer, buffer + size) {
        struct_ends_.push_back(size);
    }

    BinaryReader(const std::vector<uint8_t> data): BinaryReader(data.data(), data.size()) {
    }

    static BinaryReader FromFile(const char* filename) {
        return BinaryReader(read_file(filename));
    }

    void SetLog(ILog* log) {
        log_ = log;
    }
};