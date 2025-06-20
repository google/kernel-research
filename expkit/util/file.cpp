#pragma once

#include <cstdint>
#include <fstream>
#include <vector>
#include "util/error.cpp"

static std::vector<uint8_t> read_file(const char* filename) {
    /**
     * @brief Reads the content of a file into a vector of bytes.
     * 
     * @param filename The path to the file to read.
     * @return A vector of uint8_t containing the file's data.
     * @throws ExpKitError if the file cannot be found or opened.
     */
    std::ifstream file(filename, std::ios::binary);
    if (file.fail())
        throw ExpKitError("file not found: %s", filename);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return data;
}
/**
 * @brief Writes a string of data to a file.
 * @param filename The path to the file to write.
 * @param data The string containing the data to write.
 */
void write_file(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (file.fail())
        throw ExpKitError("file could not be written: %s", filename.c_str());
    file << data;
}
