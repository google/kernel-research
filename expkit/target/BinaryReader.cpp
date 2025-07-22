/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    uint64_t offset_ = 0;
    std::vector<uint64_t> struct_ends_;
    ILog* log_ = nullptr;
    int64_t seek_origin_offset_ = -1;
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

    uint64_t EndOffset() {
        return IsSeekingInProgress() ? data_.size() : struct_ends_.back();
    }

    uint64_t RemainingBytes() {
        return EndOffset() - offset_;
    }

    void SizeCheck(uint64_t len) {
        if (RemainingBytes() < len)
            throw ExpKitError("tried to read outside of buffer: offset=%u, len=%u, struct_end=%u", offset_, len, EndOffset());
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

    int64_t ReadInt(bool signed_ = true) {
        uint64_t byte = ReadU8();
        bool negative = signed_ && (byte & 0x40);
        uint64_t result = byte & (signed_ ? 0x3f : 0x7f);
        uint64_t shift = signed_ ? 6 : 7;
        while (byte & 0x80) {
            byte = ReadU8();
            result |= (byte & 0x7f) << shift;
            shift += 7;
        }
        return negative ? ~result : result;
    }

    uint64_t ReadUInt() {
        return ReadInt(false);
    }

    uint64_t SeekableListCount() {
        auto value = ReadUInt();
        auto offset_size = (value & 0x3) + 1;
        auto item_count = value >> 2;
        // skip the seek list
        offset_ += offset_size * item_count;
        return item_count;
    }

    bool IsSeekingInProgress() { return seek_origin_offset_ != -1; }

    void SeekToItem(uint64_t seeklist_offset, uint64_t item_idx) {
        if (IsSeekingInProgress())
            throw ExpKitError("Seeking is already in progress. Call EndSeek() first.");

        seek_origin_offset_ = offset_;
        offset_ = seeklist_offset;
        auto value = ReadUInt();
        auto offset_size = (value & 0x3) + 1;
        auto item_count = value >> 2;
        if (item_idx >= item_count)
            throw ExpKitError("tried to seek to item index %u, but list contains only %u items", item_idx, item_count);

        auto hdr_offset = offset_;
        uint64_t item_offset = 0;
        if (item_idx != 0) {
            offset_ += offset_size * (item_idx - 1);
            item_offset = Uint(offset_size);
        }

        // skip the seek list
        offset_ = hdr_offset + offset_size * item_count + item_offset;
        DebugLog("SeekToItem(): seeklist_offset=%u, item_idx=%u, offset_size=%u, item_count=%u, item_offset=%u, new offset=%u", 
            seeklist_offset, item_idx, offset_size, item_count, item_offset, offset_);
    }

    void EndSeek() {
        if (!IsSeekingInProgress())
            throw ExpKitError("There is no seeking in progress. Call SeekToItem() first.");
        offset_ = seek_origin_offset_;
        seek_origin_offset_ = -1;
    }

    template <typename... Args>
    inline void DebugLog(const char* format, const Args&... args) {
        static const char spaces[] = "                                                                     ";
        if (log_) {
            auto str = format_str(format, args...);
            log_->Log("%.*s%s%.*s[offs=%u]", log_padding, spaces, str.c_str(), 80 - log_padding - str.size(), spaces, offset_);
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

    const char* ZStr() {
        return (char*) Read(ReadUInt() + 1);
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
