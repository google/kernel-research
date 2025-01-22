#pragma once

#include <memory>
#include <optional>
#include <vector>
#include "test/TestSuite.cpp"
#include "test/TestEnvironment.cpp"
#include "test/logging/TestLogger.cpp"
#include "test/logging/PrintfLogger.cpp"
#include "util/stdutils.cpp"

class TestRunner {
    vector<unique_ptr<TestSuite>> test_suites_;
    optional<vector<string>> test_suite_filter_;
    unique_ptr<TestLogger> logger_;
    TestEnvironment environment;

public:
    TestRunner(): logger_(new PrintfLogger()) { }

    void Add(TestSuite* suite) {
        suite->env = &environment;
        test_suites_.push_back(unique_ptr<TestSuite>(suite));
    }

    void SetSuiteFilter(optional<vector<string>> filter) {
        test_suite_filter_ = filter;
    }

    void SetTargetDbPath(const std::string& target_db_path) {
        environment.SetTargetDbPath(target_db_path);
    }

    const vector<unique_ptr<TestSuite>>& GetTestSuites() {
        return test_suites_;
    }

    bool Run(uint skip = 0) {
        bool success = true;

        uint test_idx = 0;
        uint test_count = 0;
        for (auto& testSuite : test_suites_)
            test_count += testSuite->tests.size();


        logger_->Begin(test_suites_, test_count);
        for (auto& testSuite : test_suites_) {
            if (test_suite_filter_ && !contains(*test_suite_filter_, testSuite->class_name)) {
                logger_->TestSuiteSkip(*testSuite, test_idx);
                test_idx += testSuite->tests.size();
                continue;
            }

            logger_->TestSuiteBegin(*testSuite);
            try {
                testSuite->init();
            } catch(const exception& exc) {
                logger_->TestSuiteFail(*testSuite, exc);
                test_idx += testSuite->tests.size();
                success = false;
                continue;
            }

            for (auto& test : testSuite->tests) {
                if (skip > test_idx) {
                    logger_->TestSkip(*testSuite, test, test_idx++);
                    continue;
                }

                testSuite->current_test = &test;
                testSuite->logs.clear();
                testSuite->had_errors = false;
                logger_->TestBegin(*testSuite, test, test_idx);
                try {
                    test.func();
                    testSuite->AssertLogs(false);
                    testSuite->AssertNoErrors();
                    logger_->TestSuccess(*testSuite, test, test_idx);
                } catch(const exception& exc) {
                    success = false;
                    logger_->TestFail(*testSuite, test, test_idx, exc);
                }
                testSuite->current_test = nullptr;
                test_idx++;
            }
            testSuite->deinit();
            logger_->TestSuiteEnd(*testSuite);
        }

        logger_->End();
        return success;
    }

    void SetLogger(TestLogger* logger) {
        logger_.reset(logger);
    }
};
