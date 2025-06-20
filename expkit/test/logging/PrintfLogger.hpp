#pragma once

#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include "test/TestSuite.hpp"
#include "test/logging/TestLogger.hpp"

using namespace std;

class PrintfLogger: public TestLogger {
    vector<string> failed_tests_;

public:
    void Begin(const vector<unique_ptr<TestSuite>>& test_suites, uint test_count);
    void End();

    void TestSuiteBegin(const TestSuite& suite);

    void TestSuiteEnd(const TestSuite& suite);

    void TestSuiteSkip(const TestSuite& suite, uint first_test_idx);

    void TestSuiteFail(const TestSuite& suite, const std::exception& exc);

    void TestSkip(const TestSuite& suite, const Test& test, uint test_idx);

    void TestBegin(const TestSuite& suite, const Test& test, uint test_idx);

    void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx);

    void TestFail(const TestSuite& suite, const Test& test, uint test_idx,
                const exception& exc);

    void End(vector<string>& failed_tests);
};
