#pragma once

#include <memory>
#include <optional>
#include <vector>
#include "test/TestSuite.cpp"
#include "test/TestEnvironment.cpp"
#include "test/logging/TestLogger.cpp"
#include "test/logging/PrintfLogger.cpp"
#include "util/str.cpp"

struct TextFilter {
    bool must_not_exist;
    string text;
};

class ConditionMatcher {
    vector<vector<TextFilter>> filter_;

public:
    void SetFilter(const optional<string>& filter_expression) {
        filter_.clear();
        if (!filter_expression.has_value())
            return;

        for (auto& cond_expr : split(filter_expression.value(), ",")) {
            vector<TextFilter> conditions;
            for (auto& label : split(cond_expr, "+")) {
                if (startsWith(label, "^"))
                    conditions.push_back(TextFilter { true, label.substr(1) });
                else
                    conditions.push_back(TextFilter { false, label });
            }
            filter_.push_back(conditions);
        }
    }

    bool Match(const string& raw = "", const string& as_label = "") {
        if (filter_.empty())
            return true;

        for (auto& filter : filter_) {
            bool match = true;
            for (auto& lf : filter) {
                bool found = contains(raw, lf.text) ||
                    contains(as_label, "[" + lf.text + "]");
                match &= lf.must_not_exist ? !found : found;
                if (!match)
                    break;
            }
            if (match)
                return true;
        }

        return false;
    }
};

class TestRunner {
    vector<unique_ptr<TestSuite>> test_suites_;
    ConditionMatcher test_suite_filter_;
    ConditionMatcher test_filter_;
    unique_ptr<TestLogger> logger_;
    TestEnvironment environment;

    bool ShouldSkipSuite(const TestSuite& test_suite) {
        return !test_suite_filter_.Match(test_suite.class_name, test_suite.desc);
    }

    bool ShouldSkipTest(const Test& test) {
        return !test_filter_.Match(test.func_name, test.desc);
    }

public:
    TestRunner(): logger_(new PrintfLogger()) { }

    void Add(TestSuite* suite) {
        suite->env = &environment;
        test_suites_.push_back(unique_ptr<TestSuite>(suite));
    }

    void SetSuiteFilter(optional<string> filter) {
        test_suite_filter_.SetFilter(filter);
    }

    void SetTestFilter(optional<string> filter) {
        test_filter_.SetFilter(filter);
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
            if (ShouldSkipSuite(*testSuite)) {
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
                if (skip > test_idx || ShouldSkipTest(test)) {
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
