#include "test/logging/TestLogger.h"
#include "test/logging/TapLogger.h"
#include "test/TestSuite.h"

#include <kernelXDK/util/str.h>

#include <iostream>
#include <memory>
#include <vector>

using namespace std;

void TapLogger::Begin(const vector<unique_ptr<TestSuite>>& test_suites,
                      uint test_count) {
  cout << "1.." << test_count << endl;
}

void TapLogger::End() {}

void TapLogger::TestSuiteBegin(const TestSuite& suite) {
  cout << endl
       << "# Test Suite: " << suite.class_name << " (" << suite.desc << ")"
       << endl;
}

void TapLogger::TestSuiteFail(const TestSuite& suite,
                              const std::exception& exc) {
  cout << "# failed with: " << exc.what() << endl;
}

void TapLogger::TestSuiteSkip(const TestSuite& suite, uint first_test_idx) {
  uint test_idx = first_test_idx + 1;
  cout << endl
       << "# Test Suite skipped: " << suite.class_name << " (" << suite.desc
       << ")" << endl;
  for (auto& test : suite.tests)
    cout << "ok " << test_idx++ << " - " << suite.class_name
         << "::" << test.func_name << " # SKIP: test suite skipped" << endl;
}

void TapLogger::TestSuiteEnd(const TestSuite& suite) {}

void TapLogger::TestBegin(const TestSuite& suite, const Test& test,
                          uint test_idx) {}

void TapLogger::TestSuccess(const TestSuite& suite, const Test& test,
                            uint test_idx) {
  cout << "ok " << test_idx + 1 << " - " << suite.class_name
       << "::" << test.func_name << endl;
}

void TapLogger::TestFail(const TestSuite& suite, const Test& test,
                         uint test_idx, const exception& exc) {
  std::string msg = exc.what();
  replace(msg, "'", "\\'");
  cout << "not ok " << test_idx + 1 << " - " << suite.class_name
       << "::" << test.func_name << endl
       << "  ---" << endl
       << "  message: '" << msg << "'" << endl
       << "  ..." << endl;
}

void TapLogger::TestSkip(const TestSuite& suite, const Test& test,
                         uint test_idx) {
  cout << "ok " << test_idx + 1 << " - " << suite.class_name
       << "::" << test.func_name << " # SKIP: test skipped" << endl;
}
