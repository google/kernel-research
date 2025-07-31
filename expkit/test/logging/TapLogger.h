#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include "test/logging/TestLogger.h"

using namespace std;

class TapLogger: public TestLogger {
public:
    void Begin(const vector<unique_ptr<TestSuite>>& test_suites, uint test_count);

    void End();

    void TestSuiteBegin(const TestSuite& suite);

    void TestSuiteFail(const TestSuite& suite, const std::exception& exc);

    void TestSuiteSkip(const TestSuite& suite, uint first_test_idx);

    void TestSuiteEnd(const TestSuite& suite);

    void TestBegin(const TestSuite& suite, const Test& test, uint test_idx);

    void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx);

    void TestFail(const TestSuite& suite, const Test& test, uint test_idx,
                const exception& exc);

    void TestSkip(const TestSuite& suite, const Test& test, uint test_idx);
};
