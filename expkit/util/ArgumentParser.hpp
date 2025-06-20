#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include "util/str.hpp"

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
