#pragma once

#include <memory>
#include <optional>
#include <vector>
#include "test/TestSuite.cpp"
#include "test/logging/TestLogger.cpp"
#include "test/logging/PrintfLogger.cpp"
#include "util/stdutils.cpp"

class TestRunner {
    vector<unique_ptr<TestSuite>> test_suites_;
    optional<vector<string>> test_suite_filter_;
    unique_ptr<TestLogger> logger_;

public:
    TestRunner(): logger_(new PrintfLogger()) { }

    void Add(TestSuite* suite) {
        test_suites_.push_back(unique_ptr<TestSuite>(suite));
    }

    void SetSuiteFilter(optional<vector<string>> filter) {
        test_suite_filter_ = filter;
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

                logger_->TestBegin(*testSuite, test, test_idx);
                testSuite->logs.clear();
                try {
                    test.func();
                    logger_->TestSuccess(*testSuite, test, test_idx);
                } catch(const exception& exc) {
                    success = false;
                    logger_->TestFail(*testSuite, test, test_idx, exc);
                }
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
