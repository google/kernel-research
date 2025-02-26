#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

class RopChain {
public:
    uint64_t kaslr_base_;
    std::vector<uint64_t> items_;

    RopChain(uint64_t kaslr_base): kaslr_base_(kaslr_base) { }

    void Add(uint64_t item, bool offset = false) {
        items_.push_back((offset ? kaslr_base_ : 0) + item);
    }

    std::vector<uint8_t> GetData() const {
        auto result_size = items_.size() * sizeof(uint64_t);
        std::vector<uint8_t> result(result_size);
        memcpy(result.data(), items_.data(), result_size);
        return result;
    }

    uint64_t GetByteSize() const {
        return items_.size() * sizeof(uint64_t);
    }
};