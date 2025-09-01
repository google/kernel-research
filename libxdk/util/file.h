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
#include <string>
#include <vector>

/**
 * @brief Reads the content of a file into a vector of bytes.
 *
 * @param filename The path to the file to read.
 * @return A vector of uint8_t containing the file's data.
 * @throws ExpKitError if the file cannot be found or opened.
 */
std::vector<uint8_t> read_file(const std::string &filename);

/**
 * @brief Writes a string of data to a file.
 * @param filename The path to the file to write.
 * @param data The string containing the data to write.
 */
void write_file(const std::string& filename, const std::string& data);