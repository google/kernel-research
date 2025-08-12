#pragma once

#include <memory>
#include <optional>
#include <vector>
#include <string>
#include "test/TestSuite.h"
#include "test/TestEnvironment.h"
#include "test/logging/TestLogger.h"
#include "test/logging/PrintfLogger.h"

using namespace std;

struct TextFilter {
    bool must_not_exist;
    string text;
};

/**
 * @brief Handles filtering of test suites and individual tests based on provided filter expressions.
 */
class ConditionMatcher {
    vector<vector<TextFilter>> filter_;

public:
    /**
     * @brief Sets the filter for test suites.
     *
     * The filter expression is a comma-separated string of conditions. Each condition
     * is a plus-separated string of texts. A text can be negated by prefixing it with a '^'.
     *
     * For a test suite or test to match the filter, it must match at least one of the comma-separated conditions.
     * A condition is met if the test suite's or test's description or name contains all the non-negated texts
     * and none of the negated texts within that condition (separated by '+').
     */
    void SetFilter(const optional<string>& filter_expression);

    /**
    * @brief Checks if a given raw string or label matches the current filter.
    * @param raw The raw string to check for filter text.
    * @param as_label The string formatted as a label (e.g., "[label]").
    */
    bool Match(const string& raw = "", const string& as_label = "");
};

/**
 * @brief Manages and runs test suites.
 */
class TestRunner {
    vector<unique_ptr<TestSuite>> test_suites_;
    ConditionMatcher test_suite_filter_;
    ConditionMatcher test_filter_;
    uint repeat_count_ = 1;
    unique_ptr<TestLogger> logger_;
    TestEnvironment environment;

    /**
     * @brief Checks if a test suite should be skipped based on the suite filter.
     * @param test_suite The test suite to check.
     * @return True if the test suite should be skipped, false otherwise.
     */
    bool ShouldSkipSuite(const TestSuite& test_suite) {
        return !test_suite_filter_.Match(test_suite.class_name, test_suite.desc);
    }

    /**
     * @brief Checks if a test should be skipped based on the test filter.
     * @param test The test to check.
     * @return True if the test should be skipped, false otherwise.
     */
    bool ShouldSkipTest(const Test& test) {
        return !test_filter_.Match(test.func_name, test.desc);
    }

public:
    /**
     * @brief Constructs a TestRunner object.
     */
    TestRunner();

    /**
    * @brief Adds a test suite to the runner.
    * @param suite A pointer to the TestSuite to add.
    */
    void Add(TestSuite* suite);

    /**
    * @brief Sets the filter for test suites.
    * @param filter An optional string containing the filter expression.
    */
    void SetSuiteFilter(optional<string> filter);

    /**
    * @brief Sets the filter for individual tests.
    * @param filter An optional string containing the filter expression.
    */
    void SetTestFilter(optional<string> filter);

    /**
    * @brief Sets the path to the target database.
    * @param target_db_path The absolute path to the target database file.
    * @note This is forwarded to the internal TestEnvironment.
    */
    void SetTargetDbPath(const std::string& target_db_path);

    /**
    * @brief Sets the number of times each test should be repeated.
    * @param repeat_count The number of repetitions. Must be at least 1.
    * @note This is useful for testing stability.
    */
    void SetRepeatCount(uint repeat_count);

    /**
    * @brief Gets the vector of test suites managed by the runner.
    * @return A constant reference to the vector of unique pointers to TestSuite
    * objects.
    */
    const vector<unique_ptr<TestSuite>>& GetTestSuites();

    /**
    * @brief Runs the test suites according to the configured filters and repeat
    * count.
    * @param skip The number of tests to skip (in case the previous test run
    * crashed and you don't want to repeat the successful tests again).
    * @return True if all non-skipped tests passed, false otherwise.
    */
    bool Run(uint skip = 0);

    /**
    * @brief Sets the logger to be used by the test runner.
    * @param logger A pointer to the TestLogger object to use. The TestRunner
    * takes ownership of the logger.
    */
    void SetLogger(TestLogger* logger);
};
