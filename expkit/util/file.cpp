#pragma once

#include <cstdint>
#include <fstream>
#include <vector>
#include "util/error.hpp"
#include "util/file.hpp"

static std::vector<uint8_t> read_file(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (file.fail())
        throw ExpKitError("file not found: %s", filename);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return data;
}

void write_file(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (file.fail())
        throw ExpKitError("file could not be written: %s", filename.c_str());
    file << data;
}
