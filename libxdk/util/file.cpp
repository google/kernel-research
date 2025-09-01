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

#include <cstdint>
#include <fstream>
#include <vector>
#include <xdk/util/error.h>
#include "util/file.h"

std::vector<uint8_t> read_file(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (file.fail())
        throw ExpKitError("file not found: %s", filename.c_str());
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return data;
}

void write_file(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (file.fail())
        throw ExpKitError("file could not be written: %s", filename.c_str());
    file << data;
}
