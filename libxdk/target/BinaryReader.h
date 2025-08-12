#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include <kernelXDK/util/str.h>
#include "util/log.h"

class BinaryReader {
protected:
    std::vector<uint8_t> data_;
    uint64_t offset_ = 0;
    std::vector<uint64_t> struct_ends_;
    ILog* log_ = nullptr;
    int64_t seek_origin_offset_ = -1;
    unsigned int log_padding = 0;

public:
    /**
     * @brief Reads an unsigned integer of a specified size.
     * @param size The size of the unsigned integer to read (1, 2, 4, or 8 bytes).
     * @return The unsigned integer value read from the buffer.
     */
    uint64_t Uint(int size);

    /**
    * @brief Returns the end offset of the current structure or the entire data if
    * seeking is in progress.
    * @return The end offset.
    */
    uint64_t EndOffset();

    /**
    * @brief Returns the number of remaining bytes in the current structure or
    * until the end of the data if seeking is in progress.
    * @return The number of remaining bytes.
    */
    uint64_t RemainingBytes();

    /**
    * @brief Checks if there are enough remaining bytes to read a specified
    * length.
    * @param len The length to check against the remaining bytes.
    * @throws ExpKitError if there are not enough remaining bytes.
    */
    void SizeCheck(uint64_t len);

    /**
    * @brief Reads a block of raw bytes from the buffer.
    * @param len The number of bytes to read.
    * @return A pointer to the read bytes within the internal buffer.
    * @throws ExpKitError if reading beyond the buffer limits.
    */
    uint8_t* Read(uint16_t len);

    /**
    * @brief Reads a single byte (uint8_t) from the buffer.
    * @return The byte value.
    */
    uint8_t ReadU8();

    /**
    * @brief Reads a 16-bit unsigned integer (uint16_t) from the buffer.
    * @return The 16-bit unsigned integer value.
    */
    uint16_t ReadU16();

    /**
    * @brief Reads a 32-bit unsigned integer (uint32_t) from the buffer.
    * @return The 32-bit unsigned integer value.
    */
    uint32_t ReadU32();

    /**
    * @brief Reads a 64-bit unsigned integer (uint64_t) from the buffer.
    * @return The 64-bit unsigned integer value.
    */
    uint64_t ReadU64();

    /**
    * @brief Reads a variable-length integer from the buffer.
    * @param signed_ Whether the integer is signed. Defaults to true.
    * @return The integer value.
    */
    int64_t ReadInt(bool signed_ = true);

    /**
    * @brief Reads a variable-length unsigned integer from the buffer.
    * @return The unsigned integer value.
    */
    uint64_t ReadUInt();

    /**
    * @brief Reads the count of a seekable list and skips the seek list data.
    * @return The number of items in the seekable list.
    */
    uint64_t SeekableListCount();

    /**
    * @brief Checks if a seek operation is currently in progress.
    * @return True if seeking is in progress, false otherwise.
    */
    bool IsSeekingInProgress();

    /**
    * @brief Seeks to a specific item within a seekable list.
    * @param seeklist_offset The offset of the seekable list.
    * @param item_idx The index of the item to seek to.
    * @throws ExpKitError if seeking is already in progress or the item index is
    * out of bounds.
    */
    void SeekToItem(uint64_t seeklist_offset, uint64_t item_idx);

    /**
    * @brief Ends a seek operation and returns to the original offset.
    * @throws ExpKitError if no seek operation is in progress.
    */
    void EndSeek();

    /**
    * @brief Logs a debug message with the current offset.
    * @tparam Args The types of the arguments.
    * @param format The format string for the log message.
    */
    template <typename... Args>
    void DebugLog(const char* format, const Args&... args) {
        static const char spaces[] = "                                                                     ";
        if (log_) {
            auto str = format_str(format, args...);
            log_->Log("%.*s%s%.*s[offs=%u]", log_padding, spaces, str.c_str(),
                    80 - log_padding - str.size(), spaces, offset_);
        }
    }

    /**
    * @brief Begins parsing a structure. Reads the structure size and pushes the
    * end offset onto the stack.
    * @param struct_size_len The number of bytes used to specify the structure
    * size (2 or 4).
    * @param begin_if_empty If true, begins the structure even if its size is 0.
    * Defaults to true.
    * @return True if the structure is not empty or begin_if_empty is true, false
    * otherwise.
    */
    bool BeginStruct(int struct_size_len, bool begin_if_empty = true);

    /**
    * @brief Ends parsing a structure. Jumps the offset to the end of the current
    * structure.
    * @throws ExpKitError if EndStruct() is called without a corresponding
    * BeginStruct().
    */
    void EndStruct();

    /**
    * @brief Reads a null-terminated string with a specified maximum length.
    * @param len The maximum length of the string (excluding the null terminator).
    * @return A pointer to the null-terminated string within the internal buffer.
    */
    const char* ZStr(uint16_t len);

    /**
    * @brief Reads a null-terminated string where the length is encoded as a
    * variable-length unsigned integer before the string data.
    * @return A pointer to the null-terminated string within the internal buffer.
    */
    const char* ZStr();

    /**
    * @brief Constructs a BinaryReader from a raw buffer.
    * @param buffer A pointer to the raw data buffer.
    * @param size The size of the buffer.
    */
    BinaryReader(const uint8_t* buffer, size_t size);

    /**
    * @brief Constructs a BinaryReader from a vector of bytes.
    * @param data The vector of bytes.
    */
    BinaryReader(const std::vector<uint8_t> data);

    /**
    * @brief Creates a BinaryReader by reading data from a file.
    * @param filename The path to the file.
    * @return A BinaryReader instance with the file data.
    */
    static BinaryReader FromFile(const char* filename);

    /**
    * @brief Sets the logger for debug output.
    * @param log The logger object.
    */
    void SetLog(ILog* log);
};
