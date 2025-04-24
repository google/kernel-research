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

    std::optional<uint64_t> FindEmpty(uint64_t len, uint64_t alignment = 1) {
        if (len > used_bytes_.size())
            return std::nullopt;

        // O(n * k) - switch to interval tree structure?
        for (uint64_t i = 0; i < used_bytes_.size() - len; i++) {
            uint64_t j;
            for (j = 0; j < len; j++)
                if (used_bytes_[i + j])
                    break;
            if (j == len)
                return align(i, alignment);
        }

        return std::nullopt;
    }

    Payload Snapshot() {
        Payload clone(data_.size());
        clone.Restore(*this);
        return clone;
    }

    void Restore(const Payload& snapshot) {
        data_ = snapshot.data_;
        used_bytes_ = snapshot.used_bytes_;
        used_size_ = snapshot.used_size_;
    }
};
