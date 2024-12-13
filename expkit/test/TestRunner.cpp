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
    unique_ptr<TestLogger> logger_;

public:
    TestRunner(): logger_(new PrintfLogger()) { }

    void Add(TestSuite* suite) {
        test_suites_.push_back(unique_ptr<TestSuite>(suite));
    }

    const vector<unique_ptr<TestSuite>>& GetTestSuites() {
        return test_suites_;
    }

    bool Run() {
        bool success = true;

        uint test_idx = 0;
        uint test_count = 0;
        for (auto& testSuite : test_suites_)
            test_count += testSuite->tests.size();


        logger_->Begin(test_suites_, test_count);
        for (auto& testSuite : test_suites_) {
            logger_->TestSuiteBegin(*testSuite);
            testSuite->init();
            for (auto& test : testSuite->tests) {
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
