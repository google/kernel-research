#pragma once

#include <stdint.h>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <cstring>
#include "util/error.cpp"

class Payload {
    std::vector<uint8_t> data_;
    std::vector<bool> used_bytes_;

public:
    Payload(int size): data_(size), used_bytes_(size, 0) { }

    std::vector<uint8_t>& GetData() { return data_; }

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
        return data_.data() + offset;
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

    void Set(uint64_t offset, std::vector<uint8_t>& bytes) {
        Set(offset, bytes.data(), bytes.size());
    }

    void Set(uint64_t offset, uint32_t value) {
        *ReserveU32(offset) = value;
    }

    void Set(uint64_t offset, uint64_t value) {
        *ReserveU64(offset) = value;
    }

    int FindEmpty(int len) {
        // O(n * k) - switch to interval tree structure?
        for (int i = 0; i < used_bytes_.size() - len; i++) {
            int j;
            for (j = 0; j < len; j++)
                if (used_bytes_[i + j])
                    break;
            if (j == len)
                return i;
        }
        return -1;
    }

    Payload Snapshot() {
        Payload clone(data_.size());
        clone.Restore(*this);
        return clone;
    }

    void Restore(const Payload& snapshot) {
        data_ = snapshot.data_;
        used_bytes_ = snapshot.used_bytes_;
    }
};
