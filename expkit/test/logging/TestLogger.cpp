#pragma once

#include <memory>
#include <vector>
#include "test/TestSuite.cpp"

class TestLogger {
public:
    virtual void Begin(const std::vector<std::unique_ptr<TestSuite>>& test_suites, uint test_count) = 0;
    virtual void End() = 0;
    virtual void TestSuiteBegin(const TestSuite& suite) = 0;
    virtual void TestSuiteEnd(const TestSuite& suite) = 0;
    virtual void TestBegin(const TestSuite& suite, const Test& test, uint test_idx) = 0;
    virtual void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx) = 0;
    virtual void TestFail(const TestSuite& suite, const Test& test, uint test_idx, const std::exception& exc) = 0;
};

