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

/**
 * @brief Represents a single test case within a test suite.
 *
 * Stores the function name, description, and the test function itself.
 */


struct Test {
    std::string func_name;
    std::string desc;
    std::function<void()> func;

    Test(std::string func_name, std::string desc, std::function<void()> func): func_name(func_name), desc(desc), func(func) { }
};

/**
 * @brief Base class for test suites.
 *
 * Provides common functionality for running tests, logging, and asserting results.
 */
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

    /**
     * @brief Constructs a TestSuite with a class name and description.
     * @param class_name The name of the test suite class.
     * @param desc A description of the test suite.
     */
    TestSuite(std::string class_name, std::string desc): class_name(class_name), desc(desc) { }

    /** @brief Virtual method for test suite initialization. */
    virtual void init() { }

    /** @brief Virtual method for test suite deinitialization. */
    virtual void deinit() { }

    /**
     * @brief Logs a message using a format string.
     * @param format The format string for the message.
     * @param ... The arguments for the format string.
     */
    void Log(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logs.push_back(format_str(format, args));
    }

    /**
     * @brief Logs an error message and sets the had_errors flag.
     * @param format The format string for the error message.
     * @param ... The arguments for the format string.
     */
    void Error(const char* format, ...) {
        va_list args;
        va_start(args, format);
        logs.push_back(format_str(format, args));
        had_errors = true;
    }

    /**
     * @brief Registers a test case with the test suite.
     * @param test The Test object to register.
     * @return A reference to the registered Test object.
     */
    Test& RegisterTest(Test test) {
        tests.push_back(test);
        return tests.back();
    }

    /**
     * @brief Asserts that the logged output matches the expected results in a file.
     * @param fail_if_no_expected If true, the test will fail if no expected results file is found.
     */
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

    /**
     * @brief Asserts that no errors have occurred during the test execution.
     * @throws ExpKitError if the had_errors flag is true.
     */
    void AssertNoErrors() {
        if (had_errors)
            throw ExpKitError("the test failed with errors");
    }
};