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
    /**
     * @brief Reads an unsigned integer of a specified size.
     * @param size The size of the unsigned integer to read (1, 2, 4, or 8 bytes).
     * @return The unsigned integer value read from the buffer.
     */
    uint64_t Uint(int size) {
        if (size == 1) return ReadU8();
        else if (size == 2) return ReadU16();
        else if (size == 4) return ReadU32();
        else if (size == 8) return ReadU64();
        else
            throw ExpKitError("unsupported uint size (%d)", size);
    }

    /**
     * @brief Returns the end offset of the current structure or the entire data if seeking is in progress.
     * @return The end offset.
     */
    uint64_t EndOffset() {
        return IsSeekingInProgress() ? data_.size() : struct_ends_.back();
    }

    /**
     * @brief Returns the number of remaining bytes in the current structure or until the end of the data if seeking is in progress.
     * @return The number of remaining bytes.
     */
    uint64_t RemainingBytes() {
        return EndOffset() - offset_;
    }

    /**
     * @brief Checks if there are enough remaining bytes to read a specified length.
     * @param len The length to check against the remaining bytes.
     * @throws ExpKitError if there are not enough remaining bytes.
     */
    void SizeCheck(uint64_t len) {
        if (RemainingBytes() < len)
            throw ExpKitError("tried to read outside of buffer: offset=%u, len=%u, struct_end=%u", offset_, len, EndOffset());
    }

    /**
     * @brief Reads a block of raw bytes from the buffer.
     * @param len The number of bytes to read.
     * @return A pointer to the read bytes within the internal buffer.
     * @throws ExpKitError if reading beyond the buffer limits.
     */
    uint8_t* Read(uint16_t len) {
        SizeCheck(len);
        uint8_t* ptr = &data_.data()[offset_];
        offset_ += len;
        return ptr;
    }

    /**
     * @brief Reads a single byte (uint8_t) from the buffer.
     * @return The byte value.
     */
    uint8_t ReadU8() {
        return *(uint8_t*)Read(1);
    }

    /**
     * @brief Reads a 16-bit unsigned integer (uint16_t) from the buffer.
     * @return The 16-bit unsigned integer value.
     */
    uint16_t ReadU16() {
        return *(uint16_t*)Read(2);
    }

    /**
     * @brief Reads a 32-bit unsigned integer (uint32_t) from the buffer.
     * @return The 32-bit unsigned integer value.
     */
    uint32_t ReadU32() {
        return *(uint32_t*)Read(4);
    }

    /**
     * @brief Reads a 64-bit unsigned integer (uint64_t) from the buffer.
     * @return The 64-bit unsigned integer value.
     */
    uint64_t ReadU64() {
        return *(uint64_t*)Read(8);
    }

    /**
     * @brief Reads a variable-length integer from the buffer.
     * @param signed_ Whether the integer is signed. Defaults to true.
     * @return The integer value.
     */
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

    /**
     * @brief Reads a variable-length unsigned integer from the buffer.
     * @return The unsigned integer value.
     */
    uint64_t ReadUInt() {
        return ReadInt(false);
    }

    /**
     * @brief Reads the count of a seekable list and skips the seek list data.
     * @return The number of items in the seekable list.
     */
    uint64_t SeekableListCount() {
        auto value = ReadUInt();
        auto offset_size = (value & 0x3) + 1;
        auto item_count = value >> 2;
        // skip the seek list
        offset_ += offset_size * item_count;
        return item_count;
    }

    /**
     * @brief Checks if a seek operation is currently in progress.
     * @return True if seeking is in progress, false otherwise.
     */
    bool IsSeekingInProgress() { return seek_origin_offset_ != -1; }

    /**
     * @brief Seeks to a specific item within a seekable list.
     * @param seeklist_offset The offset of the seekable list.
     * @param item_idx The index of the item to seek to.
     * @throws ExpKitError if seeking is already in progress or the item index is out of bounds.
     */
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

    /**
     * @brief Ends a seek operation and returns to the original offset.
     * @throws ExpKitError if no seek operation is in progress.
     */
    void EndSeek() {
        if (!IsSeekingInProgress())
            throw ExpKitError("There is no seeking in progress. Call SeekToItem() first.");
        offset_ = seek_origin_offset_;
        seek_origin_offset_ = -1;
    }

    /**
     * @brief Logs a debug message with the current offset.
     * @tparam Args The types of the arguments.
     * @param format The format string for the log message.
     */
    template <typename... Args>
    inline void DebugLog(const char* format, const Args&... args) {
        static const char spaces[] = "                                                                     ";
        if (log_) {
            auto str = format_str(format, args...);
            log_->Log("%.*s%s%.*s[offs=%u]", log_padding, spaces, str.c_str(), 80 - log_padding - str.size(), spaces, offset_);
        }
    }

    /**
     * @brief Begins parsing a structure. Reads the structure size and pushes the end offset onto the stack.
     * @param struct_size_len The number of bytes used to specify the structure size (2 or 4).
     * @param begin_if_empty If true, begins the structure even if its size is 0. Defaults to true.
     * @return True if the structure is not empty or begin_if_empty is true, false otherwise.
     */
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

    /**
     * @brief Ends parsing a structure. Jumps the offset to the end of the current structure.
     * @throws ExpKitError if EndStruct() is called without a corresponding BeginStruct().
     */
    void EndStruct() {
        if (struct_ends_.empty())
            throw ExpKitError("cannot call EndStruct() if BeginStruct() was not called before");
        DebugLog("EndStruct(): jumping to offset %u (not parsed bytes in struct: %u)", struct_ends_.back(), RemainingBytes());
        offset_ = struct_ends_.back();
        struct_ends_.pop_back();
        log_padding -= 2;
    }

    /**
     * @brief Reads a null-terminated string with a specified maximum length.
     * @param len The maximum length of the string (excluding the null terminator).
     * @return A pointer to the null-terminated string within the internal buffer.
     */
    const char* ZStr(uint16_t len) {
        return (char*) Read(len + 1);
    }

    /**
     * @brief Reads a null-terminated string where the length is encoded as a variable-length unsigned integer before the string data.
     * @return A pointer to the null-terminated string within the internal buffer.
     */
    const char* ZStr() {
        return (char*) Read(ReadUInt() + 1);
    }

    /**
     * @brief Constructs a BinaryReader from a raw buffer.
     * @param buffer A pointer to the raw data buffer.
     * @param size The size of the buffer.
     */
    BinaryReader(const uint8_t* buffer, size_t size): data_(buffer, buffer + size) {
        struct_ends_.push_back(size);
    }

    /**
     * @brief Constructs a BinaryReader from a vector of bytes.
     * @param data The vector of bytes.
     */
    BinaryReader(const std::vector<uint8_t> data): BinaryReader(data.data(), data.size()) {
    }

    /**
     * @brief Creates a BinaryReader by reading data from a file.
     * @param filename The path to the file.
     * @return A BinaryReader instance with the file data.
     */
    static BinaryReader FromFile(const char* filename) {
        return BinaryReader(read_file(filename));
    }

    /**
     * @brief Sets the logger for debug output.
     * @param log The logger object.
     */
    void SetLog(ILog* log) {
        log_ = log;
    }
};