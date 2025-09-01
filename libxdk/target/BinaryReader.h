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

#include <xdk/util/str.h>
#include "util/log.h"

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @class BinaryReader
 * @brief A class for reading and parsing data from a binary buffer with offset tracking and structural awareness.
 */
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
    * @brief Skip len amount of bytes.
    * @param len The number of bytes to skip.
    * @throws ExpKitError if there are not enough remaining bytes.
    */
    void Skip(uint64_t len);

    /**
    * @brief Seek to offset.
    * @param offset The offset within the file to seek.
    * @throws ExpKitError if the offset is out-of-bounds.
    */
    void SeekTo(uint64_t offset);

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

    std::vector<uint64_t> IndexableIntList();
    std::vector<uint64_t> SeekableListSizes();

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
        static const char spaces[] = "                                                                                ";
        if (log_) {
            auto str = format_str(format, args...);
            log_->Log("%.*s%s%.*s[offs=%u]", log_padding, spaces, str.c_str(),
                      80 - log_padding - str.size(), spaces, offset_);
        }
    }

    /**
    * @brief Limits the reader to struct_size.
    * @param struct_size The structure size in bytes.
    * @returns struct_size is not zero.
    */
    bool BeginStruct(uint64_t struct_size);

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
