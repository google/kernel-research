#include <kernelXDK/payloads/Payload.hpp>
#include <kernelXDK/util/error.hpp>
#include "util/math_utils.hpp"
#include <cstring>
#include <stdexcept>

Payload::Payload(int size): data_(size), used_bytes_(size, 0), used_size_(0) { }

Payload::Payload(const Payload& other)
        : data_(other.data_),
          used_bytes_(other.used_bytes_),
          used_size_(other.used_size_) {}

size_t Payload::Size() { return data_.size(); }

std::vector<uint8_t>& Payload::GetData() { return data_; }

std::vector<uint8_t> Payload::GetUsedData() const {
    return std::vector<uint8_t>(data_.begin(), data_.begin() + used_size_);
}

bool Payload::CheckFree(uint64_t offset, uint64_t len, bool throws) {
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

uint8_t* Payload::Reserve(uint64_t offset, uint64_t len) {
    CheckFree(offset, len, true);
    std::fill_n(used_bytes_.begin() + offset, len, true);
    if (offset + len > used_size_)
        used_size_ = offset + len;
    return data_.data() + offset;
}

void Payload::Release(uint64_t offset, uint64_t len) {
    std::fill_n(used_bytes_.begin() + offset, len, false);
    if (offset + len == used_size_)
        used_size_ = offset;
}

// this assumes that the buffer won't be moved in memory
uint64_t* Payload::ReserveU64(uint64_t offset) {
    Reserve(offset, sizeof(uint64_t));
    return (uint64_t*) &data_[offset];
}

// this assumes that the buffer won't be moved in memory
uint32_t* Payload::ReserveU32(uint64_t offset) {
    Reserve(offset, sizeof(uint32_t));
    return (uint32_t*) &data_[offset];
}

void Payload::Set(uint64_t offset, void* src, size_t len) {
    Reserve(offset, len);
    std::memcpy(&data_[offset], src, len);
}

void Payload::Set(uint64_t offset, const std::vector<uint8_t>& bytes) {
    Set(offset, (void*) bytes.data(), bytes.size());
}

void Payload::Set(uint64_t offset, uint32_t value) {
    *ReserveU32(offset) = value;
}

void Payload::Set(uint64_t offset, uint64_t value) {
    *ReserveU64(offset) = value;
}

std::optional<uint64_t> Payload::FindEmpty(uint64_t len, uint64_t alignment, uint64_t min_offset) {
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

Payload Payload::Snapshot() {
    return Payload(*this);
}

void Payload::Restore(const Payload& snapshot) {
    data_ = snapshot.data_;
    used_bytes_ = snapshot.used_bytes_;
    used_size_ = snapshot.used_size_;
}
