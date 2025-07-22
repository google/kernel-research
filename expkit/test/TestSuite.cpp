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

#include <functional>
#include <string>
#include <vector>
#include "test/TestEnvironment.cpp"
#include "util/log.cpp"
#include "util/str.cpp"

#define TEST_METHOD(name, desc) \
    Test _test_ ## name = RegisterTest(Test(#name, desc, [this]() { name(); })); \
    void name()

struct Test {
    std::string func_name;
    std::string desc;
    std::function<void()> func;

    Test(std::string func_name, std::string desc, std::function<void()> func): func_name(func_name), desc(desc), func(func) { }
};

struct TestSuite: ILog {
    std::string class_name;
    std::string desc;
    std::vector<Test> tests;
    std::vector<std::string> logs;
    std::vector<std::string> errors;
    TestEnvironment* env;
    Test* current_test;
    bool had_errors = false;

    TestSuite() {}
    TestSuite(std::string class_name, std::string desc): class_name(class_name), desc(desc) { }

    virtual void init() { }
    virtual void deinit() { }

    void Log(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logs.push_back(format_str(format, args));
    }

    void Error(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logs.push_back(format_str(format, args));
        had_errors = true;
    }

    Test& RegisterTest(Test test) {
        tests.push_back(test);
        return tests.back();
    }

    void AssertLogs(bool fail_if_no_expected = true) {
        std::string filename = class_name + "_" + current_test->func_name + ".txt";

        try {
            std::ifstream input_file(std::string("test/artifacts/expected_results/") + filename);
            if (input_file.fail()) {
                if (fail_if_no_expected)
                    throw ExpKitError("expected results file for test %s is missing", filename.c_str());
                return;
            }

            int i = 0;
            std::string line;
            for (; std::getline(input_file, line); i++) {
                if (i >= logs.size())
                    throw ExpKitError("expected more lines than %u", logs.size());
                if (line.compare(logs[i]))
                    throw ExpKitError("expected '%s' but got '%s' for test log %s line %u", line.c_str(), logs[i].c_str(), filename.c_str(), i + 1);
            }

            if (i + 1 < logs.size())
                throw ExpKitError("expected %u lines but got %u", i + 1, logs.size());
        } catch (const std::exception& e) {
            write_file(std::string("test/artifacts/actual_results/") + filename,
                str_concat("\n", logs));
            throw;
        }
    }

    void AssertNoErrors() {
        if (had_errors)
            throw ExpKitError("the test failed with errors");
    }
};
