#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include "util/str.cpp"

using namespace std;

class ArgumentParser {
public:
    /**
     * @brief Parses command line arguments.
     *
     * @param argc The number of command line arguments.
     * @param argv An array of C-style strings representing the command line arguments.
     */
    ArgumentParser(int argc, const char* argv[]) {
        vector<string> args(argv, argv + argc);

        for (size_t i = 1; i < args.size(); ++i) {
            auto arg = args[i];

            size_t hyphenCount = 0;
            while (hyphenCount < arg.size() && arg[hyphenCount] == '-')
                hyphenCount++;

            if (hyphenCount == 0) {
                positionalArgs_.push_back(arg);
            } else {
                arg = arg.substr(hyphenCount);

                string value = "";
                if (i + 1 < args.size() && !args[i + 1].empty() && args[i + 1][0] != '-') {
                    value = args[i + 1];
                    i++;
                }

                if (options_.count(arg) > 0)
                    options_[arg] += "," + value;
                else
                    options_[arg] = value;
            }
        }
    }

    /**
     * @brief Gets all parsed options.
     *
     * @return A map where keys are option names and values are option values.
     */
    const map<string, string>& getOptions() const {
        return options_;
    }

    /**
     * @brief Gets the value of a specific option.
     *
     * @param name The name of the option.
     * @return An optional containing the option value if found, otherwise nullopt.
     */
    optional<string> getOption(const string& name) const {
        auto it = options_.find(name);
        return it != options_.end() ? optional(it->second) : nullopt;
    }

    /**
     * @brief Checks if a specific option exists.
     *
     * @param name The name of the option.
     * @return True if the option exists, false otherwise.
     */
    bool hasOption(const string& name) const {
        return options_.find(name) != options_.end();
    }

    optional<long> getInt(const string& name) const {
        auto it = options_.find(name);
        return it != options_.end() ? optional(stoi(it->second)) : nullopt;
    }

    /**
     * @brief Gets the option value as a list separated by comma.
     *
     * @param name The name of the option.
     * @return An optional containing a vector of strings if the option is found, otherwise nullopt.
     */
    optional<vector<string>> getListOption(const string& name) const {
        auto it = options_.find(name);
        return it != options_.end() ? optional(split(it->second, ",")) : nullopt;
    }

    /**
     * @brief Gets the positional arguments.
     * @return A vector of strings containing the positional arguments.
     */
    const vector<string>& getPositionalArgs() const {
        return positionalArgs_;
    }

private:
    map<string, string> options_;
    vector<string> positionalArgs_;
};