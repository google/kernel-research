#include "target/BinaryReader.h"
#include <cstdint>
#include <cstring>
#include <vector>
#include <kernelXDK/util/error.h>
#include "util/file.h"
#include "util/log.h"

void BinaryReader::SetLog(ILog* log) { log_ = log; }

BinaryReader::BinaryReader(const std::vector<uint8_t> data)
    : BinaryReader(data.data(), data.size()) {}

BinaryReader BinaryReader::FromFile(const char* filename) {
  return BinaryReader(read_file(filename));
}

BinaryReader::BinaryReader(const uint8_t* buffer, size_t size)
    : data_(buffer, buffer + size) {
  struct_ends_.push_back(size);
}

const char* BinaryReader::ZStr() { return (char*)Read(ReadUInt() + 1); }

const char* BinaryReader::ZStr(uint16_t len) { return (char*)Read(len + 1); }

void BinaryReader::EndStruct() {
  if (struct_ends_.empty())
    throw ExpKitError(
        "cannot call EndStruct() if BeginStruct() was not called before");
  DebugLog("EndStruct(): jumping to offset %u (not parsed bytes in struct: %u)",
           struct_ends_.back(), RemainingBytes());
  offset_ = struct_ends_.back();
  struct_ends_.pop_back();
  log_padding -= 2;
}

bool BinaryReader::BeginStruct(int struct_size_len, bool begin_if_empty) {
  if (struct_size_len != 2 && struct_size_len != 4)
    throw ExpKitError(
        "unsupported struct_size_len (%d), only 2 and 4 supported",
        struct_size_len);

  auto struct_size = struct_size_len == 2 ? ReadU16() : ReadU32();
  DebugLog("BeginStruct(): offset = %u, struct_size = %u, end_offset = %u",
           offset_, struct_size, offset_ + struct_size);
  SizeCheck(struct_size);
  bool empty = struct_size == 0;
  if (!empty || begin_if_empty) {
    struct_ends_.push_back(offset_ + struct_size);
    log_padding += 2;
  }
  return !empty;
}

void BinaryReader::EndSeek() {
  if (!IsSeekingInProgress())
    throw ExpKitError(
        "There is no seeking in progress. Call SeekToItem() first.");
  offset_ = seek_origin_offset_;
  seek_origin_offset_ = -1;
}

void BinaryReader::SeekToItem(uint64_t seeklist_offset, uint64_t item_idx) {
  if (IsSeekingInProgress())
    throw ExpKitError("Seeking is already in progress. Call EndSeek() first.");

  seek_origin_offset_ = offset_;
  offset_ = seeklist_offset;
  auto value = ReadUInt();
  auto offset_size = (value & 0x3) + 1;
  auto item_count = value >> 2;
  if (item_idx >= item_count)
    throw ExpKitError(
        "tried to seek to item index %u, but list contains only %u items",
        item_idx, item_count);

  auto hdr_offset = offset_;
  uint64_t item_offset = 0;
  if (item_idx != 0) {
    offset_ += offset_size * (item_idx - 1);
    item_offset = Uint(offset_size);
  }

  // skip the seek list
  offset_ = hdr_offset + offset_size * item_count + item_offset;
  DebugLog(
      "SeekToItem(): seeklist_offset=%u, item_idx=%u, offset_size=%u, "
      "item_count=%u, item_offset=%u, new offset=%u",
      seeklist_offset, item_idx, offset_size, item_count, item_offset, offset_);
}

bool BinaryReader::IsSeekingInProgress() { return seek_origin_offset_ != -1; }

uint64_t BinaryReader::SeekableListCount() {
  auto value = ReadUInt();
  auto offset_size = (value & 0x3) + 1;
  auto item_count = value >> 2;
  // skip the seek list
  offset_ += offset_size * item_count;
  return item_count;
}

uint64_t BinaryReader::ReadUInt() { return ReadInt(false); }

int64_t BinaryReader::ReadInt(bool signed_) {
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

uint64_t BinaryReader::ReadU64() { return *(uint64_t*)Read(8); }

uint32_t BinaryReader::ReadU32() { return *(uint32_t*)Read(4); }

uint16_t BinaryReader::ReadU16() { return *(uint16_t*)Read(2); }

uint8_t BinaryReader::ReadU8() { return *(uint8_t*)Read(1); }

uint8_t* BinaryReader::Read(uint16_t len) {
  SizeCheck(len);
  uint8_t* ptr = &data_.data()[offset_];
  offset_ += len;
  return ptr;
}

void BinaryReader::SizeCheck(uint64_t len) {
  if (RemainingBytes() < len)
    throw ExpKitError(
        "tried to read outside of buffer: offset=%u, len=%u, struct_end=%u",
        offset_, len, EndOffset());
}

uint64_t BinaryReader::RemainingBytes() { return EndOffset() - offset_; }

uint64_t BinaryReader::EndOffset() {
  return IsSeekingInProgress() ? data_.size() : struct_ends_.back();
}

uint64_t BinaryReader::Uint(int size) {
  if (size == 1)
    return ReadU8();
  else if (size == 2)
    return ReadU16();
  else if (size == 4)
    return ReadU32();
  else if (size == 8)
    return ReadU64();
  else
    throw ExpKitError("unsupported uint size (%d)", size);
}
