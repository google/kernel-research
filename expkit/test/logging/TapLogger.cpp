#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include "test/logging/TestLogger.cpp"

using namespace std;

class TapLogger: public TestLogger {
public:
    void Begin(const vector<unique_ptr<TestSuite>>& test_suites, uint test_count) {
        cout << "1.." << test_count << endl;
    }

    void End() { }

    void TestSuiteBegin(const TestSuite& suite) {
        cout << endl << "# Test Suite: " << suite.class_name << " (" << suite.desc << ")" << endl;
    }

    void TestSuiteSkip(const TestSuite& suite, uint first_test_idx) {
        uint test_idx = first_test_idx + 1;
        cout << endl << "# Test Suite skipped: " << suite.class_name << " (" << suite.desc << ")" << endl;
        for (auto& test : suite.tests)
            cout << "ok " << test_idx++ << " - " << suite.class_name << "::" << test.func_name << " # SKIP: test suite skipped" << endl;
    }

    void TestSuiteEnd(const TestSuite& suite) { }

    void TestBegin(const TestSuite& suite, const Test& test, uint test_idx) { }

    void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx) {
        cout << "ok " << test_idx + 1 << " - " << suite.class_name << "::" << test.func_name << endl;
    }

    void TestFail(const TestSuite& suite, const Test& test, uint test_idx, const exception& exc) {
        std::string msg = exc.what();
        replace(msg, "'", "\\'");
        cout << "not ok " << test_idx + 1 << " - " << suite.class_name << "::" << test.func_name << endl
             << "  ---" << endl
             << "  message: '" << msg << "'" << endl
             << "  ..." << endl;
    }

    void TestSkip(const TestSuite& suite, const Test& test, uint test_idx) {
        cout << "ok " << test_idx + 1 << " - " << suite.class_name << "::" << test.func_name << " # SKIP: test skipped" << endl;
    }
};
