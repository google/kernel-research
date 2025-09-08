// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <xdk/leak/LeakedBuffer.h>
#include "xdk/util/error.h"

LeakedBuffer::LeakedBuffer(Target& target, std::vector<uint8_t> data): target_(target), data_(data) { }

uint64_t LeakedBuffer::Read(uint64_t offset, size_t size) {
  if (offset > data_.size() - size)
    throw ExpKitError("reading out of leaked buffer: offset=%lu, read size=%lu, buffer_size=%lu", offset, size, data_.size());

  auto ptr = &data_[offset];
  if (size == 1)
    return *ptr;
  else if (size == 2)
    return *(uint16_t*)ptr;
  else if (size == 4)
    return *(uint32_t*)ptr;
  else if (size == 8)
    return *(uint64_t*)ptr;

  throw ExpKitError("unsupported read size: %lu, supported sizes: 1, 2, 4 and 8", size);
}

std::map<std::string, uint64_t> LeakedBuffer::GetStruct(const std::string& struct_name, int64_t struct_offset) {
  std::map<std::string, uint64_t> result;
  for (auto field : target_.GetStruct(struct_name).fields)
    result[field.first] = Read(struct_offset + field.second.offset, field.second.size);
  return result;
}

uint64_t LeakedBuffer::GetField(const std::string& struct_name, const std::string& field_name, int64_t struct_offset) {
  auto str = target_.GetStruct(struct_name);
  auto field = str.fields.at(field_name);
  return Read(struct_offset + field.offset, field.size);
}
