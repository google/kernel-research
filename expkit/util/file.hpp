#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Reads the content of a file into a vector of bytes.
 *
 * @param filename The path to the file to read.
 * @return A vector of uint8_t containing the file's data.
 * @throws ExpKitError if the file cannot be found or opened.
 */
static std::vector<uint8_t> read_file(const char* filename);

/**
 * @brief Writes a string of data to a file.
 * @param filename The path to the file to write.
 * @param data The string containing the data to write.
 */
void write_file(const std::string& filename, const std::string& data);