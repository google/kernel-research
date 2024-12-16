#pragma once

#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include "test/TestSuite.cpp"
#include "test/logging/TestLogger.cpp"

#define RED(s)    "\033[1;31m" << s << "\033[0;0m"
#define GREEN(s)  "\033[1;32m" << s << "\033[0;0m"
#define YELLOW(s) "\033[1;33m" << s << "\033[0;0m"

using namespace std;

class PrintfLogger: public TestLogger {
    vector<string> failed_tests_;

public:
    void Begin(const vector<unique_ptr<TestSuite>>& test_suites, uint test_count) { }
    void End() { }

    void TestSuiteBegin(const TestSuite& suite) {
        cout << "===== TEST SUITE ::: " YELLOW(suite.class_name) " (" << suite.desc << ") ::: =====" << endl;
    }

    void TestSuiteEnd(const TestSuite& suite) {
        cout << endl;
    }

    void TestSuiteSkip(const TestSuite& suite, uint first_test_idx) { }

    void TestSuiteFail(const TestSuite& suite, const std::exception& exc) {
        cout << "[!] Test suite failed with: " RED(exc.what()) << endl << endl;
    }

    void TestSkip(const TestSuite& suite, const Test& test, uint test_idx) {
        cout << "[-] Skipping test: " YELLOW(test.func_name) " (" << test.desc << ") " << endl;
    }

    void TestBegin(const TestSuite& suite, const Test& test, uint test_idx) {
        cout << "[+] Running test: " YELLOW(test.func_name) " (" << test.desc << ") " << endl;
    }

    void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx) {
        cout << "[+] Test ran successfully." << endl;
    }

    void TestFail(const TestSuite& suite, const Test& test, uint test_idx, const exception& exc) {
        failed_tests_.push_back(format_str("%s::%s", suite.class_name.c_str(), test.func_name.c_str()));

        cout << "[!] Test failed with: " RED(exc.what()) << endl;
        if (!suite.logs.empty()) {
            cout << "  Logs:" << endl;
            for (auto& log : suite.logs)
                cout << "    " << log << endl;
        }
    }

    void End(vector<string>& failed_tests) {
        cout << endl << "===== SUMMARY =====" << endl;
        if (failed_tests.empty())
            cout << "[+] " GREEN("SUCCESS") "." << endl;
        else
            cout << "[!] " RED("FAIL") ".\n[!] The following tests failed: " RED(str_concat(", ", failed_tests)) << endl;

    }
};
