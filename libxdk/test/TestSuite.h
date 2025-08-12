#pragma once

#include <functional>
#include <string>
#include <vector>
#include "test/TestEnvironment.h"
#include "util/log.h"

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

    Test(std::string func_name, std::string desc, std::function<void()> func);
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

    TestSuite();

    /**
     * @brief Constructs a TestSuite with a class name and description.
     * @param class_name The name of the test suite class.
     * @param desc A description of the test suite.
     */
    TestSuite(std::string class_name, std::string desc);

    /** @brief Virtual method for test suite initialization. */
    virtual void init();

    /** @brief Virtual method for test suite deinitialization. */
    virtual void deinit();

    /**
     * @brief Logs a message using a format string.
     * @param format The format string for the message.
     * @param ... The arguments for the format string.
     */
    void Log(const char* format, ...);

    /**
     * @brief Logs an error message and sets the had_errors flag.
     * @param format The format string for the error message.
     * @param ... The arguments for the format string.
     */
    void Error(const char* format, ...);

    /**
     * @brief Registers a test case with the test suite.
     * @param test The Test object to register.
     * @return A reference to the registered Test object.
     */
    Test& RegisterTest(Test test);

    /**
     * @brief Asserts that the logged output matches the expected results in a file.
     * @param fail_if_no_expected If true, the test will fail if no expected results file is found.
     */
    void AssertLogs(bool fail_if_no_expected = true);

    /**
     * @brief Asserts that no errors have occurred during the test execution.
     * @throws ExpKitError if the had_errors flag is true.
     */
    void AssertNoErrors();
};
