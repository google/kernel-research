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

#include <stdint.h>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <cstring>
#include <optional>
#include "util/error.cpp"
#include "util/math_utils.cpp"

class Payload {
    std::vector<uint8_t> data_;
    std::vector<bool> used_bytes_;
    uint64_t used_size_;

public:
    Payload(int size): data_(size), used_bytes_(size, 0), used_size_(0) { }

    Payload(const Payload& other)
        : data_(other.data_),
          used_bytes_(other.used_bytes_),
          used_size_(other.used_size_) {}

    size_t Size() { return data_.size(); }

    std::vector<uint8_t>& GetData() { return data_; }

    std::vector<uint8_t> GetUsedData() const {
        return std::vector<uint8_t>(data_.begin(), data_.begin() + used_size_);
    }

    bool CheckFree(uint64_t offset, uint64_t len, bool throws = false) {
        if (offset + len > data_.size()) {
            if (throws)
                throw ExpKitError("buffer (%u) is not big enough to store this data (offs: %u, len: %u)", data_.size(), offset, len);
            return false;
        }

        for (int i = 0; i < len; i++)
            if (used_bytes_[offset + i]) {
                if (throws)
                    throw ExpKitError("there is already data at this offset: 0x%x", offset + i);
                return false;
            }

        return true;
    }

    uint8_t* Reserve(uint64_t offset, uint64_t len) {
        CheckFree(offset, len, true);
        std::fill_n(used_bytes_.begin() + offset, len, true);
        if (offset + len > used_size_)
            used_size_ = offset + len;
        return data_.data() + offset;
    }

    void Release(uint64_t offset, uint64_t len) {
        std::fill_n(used_bytes_.begin() + offset, len, false);
        if (offset + len == used_size_)
            used_size_ = offset;
    }

    // this assumes that the buffer won't be moved in memory
    uint64_t* ReserveU64(uint64_t offset) {
        Reserve(offset, sizeof(uint64_t));
        return (uint64_t*) &data_[offset];
    }

    // this assumes that the buffer won't be moved in memory
    uint32_t* ReserveU32(uint64_t offset) {
        Reserve(offset, sizeof(uint32_t));
        return (uint32_t*) &data_[offset];
    }

    void Set(uint64_t offset, void* src, size_t len) {
        Reserve(offset, len);
        std::memcpy(&data_[offset], src, len);
    }

    void Set(uint64_t offset, const std::vector<uint8_t>& bytes) {
        Set(offset, (void*) bytes.data(), bytes.size());
    }

    void Set(uint64_t offset, uint32_t value) {
        *ReserveU32(offset) = value;
    }

    void Set(uint64_t offset, uint64_t value) {
        *ReserveU64(offset) = value;
    }

    std::optional<uint64_t> FindEmpty(uint64_t len, uint64_t alignment = 1, uint64_t min_offset=0) {
        if (len > used_bytes_.size())
            return std::nullopt;

        // Ensure min_offset is aligned.
        min_offset = align(min_offset, alignment);

        // check for len contiguous unused bytes
        // When we encounter a used_byte we increment i beyond it
        // algorithm is O(n)
        uint64_t i = min_offset;
        while (i <= used_bytes_.size() - len) {
            bool found = true;
            for (uint64_t j = 0; j < len; j++) {
                if (used_bytes_[i + j]) {
                    found = false;
                    i = align(i+j+1, alignment); //Increment past the used byte, and ensure alignment.
                    break;
                }
            }

            if (found) {
                return i;
            }
        }

        return std::nullopt;
    }

    Payload Snapshot() {
        return Payload(*this);
    }

    void Restore(const Payload& snapshot) {
        data_ = snapshot.data_;
        used_bytes_ = snapshot.used_bytes_;
        used_size_ = snapshot.used_size_;
    }
};
