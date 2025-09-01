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

#include <string>
#include <vector>
#include <map>
#include <optional>

using namespace std;

class ArgumentParser {
public:
    /**
     * @brief Parses command line arguments.
     *
     * @param argc The number of command line arguments.
     * @param argv An array of C-style strings representing the command line arguments.
     */
 ArgumentParser(int argc, const char* argv[]);

 /**
  * @brief Gets all parsed options.
  *
  * @return A map where keys are option names and values are option values.
  */
 const map<string, string>& getOptions() const;

 /**
  * @brief Gets the value of a specific option.
  *
  * @param name The name of the option.
  * @return An optional containing the option value if found, otherwise nullopt.
  */
 optional<string> getOption(const string& name) const;

 /**
  * @brief Checks if a specific option exists.
  *
  * @param name The name of the option.
  * @return True if the option exists, false otherwise.
  */
 bool hasOption(const string& name) const;

 optional<long> getInt(const string& name) const;

 /**
  * @brief Gets the option value as a list separated by comma.
  *
  * @param name The name of the option.
  * @return An optional containing a vector of strings if the option is found,
  * otherwise nullopt.
  */
 optional<vector<string>> getListOption(const string& name) const;

 /**
  * @brief Gets the positional arguments.
  * @return A vector of strings containing the positional arguments.
  */
 const vector<string>& getPositionalArgs() const;

private:
 map<string, string> options_;
 vector<string> positionalArgs_;
};
