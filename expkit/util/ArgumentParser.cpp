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
#include "util/str.cpp"

using namespace std;

class ArgumentParser {
public:
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

    const map<string, string>& getOptions() const {
        return options_;
    }

    optional<string> getOption(const string& name) const {
        auto it = options_.find(name);
        return it != options_.end() ? optional(it->second) : nullopt;
    }

    bool hasOption(const string& name) const {
        return options_.find(name) != options_.end();
    }

    optional<long> getInt(const string& name) const {
        auto it = options_.find(name);
        return it != options_.end() ? optional(stoi(it->second)) : nullopt;
    }

    optional<vector<string>> getListOption(const string& name) const {
        auto it = options_.find(name);
        return it != options_.end() ? optional(split(it->second, ",")) : nullopt;
    }

    const vector<string>& getPositionalArgs() const {
        return positionalArgs_;
    }

private:
    map<string, string> options_;
    vector<string> positionalArgs_;
};
