#include <functional>
#include <string>
#include <vector>
#include "test/TestSuite.hpp"
#include "util/file.hpp"
#include <kernelXDK/util/error.hpp>
#include <fstream>

#define TEST_METHOD(name, desc) \
    Test _test_ ## name = RegisterTest(Test(#name, desc, [this]() { name(); })); \
    void name()

Test::Test(std::string func_name, std::string desc, std::function<void()> func)
    : func_name(func_name), desc(desc), func(func) {}

TestSuite::TestSuite() {}

TestSuite::TestSuite(std::string class_name, std::string desc)
    : class_name(class_name), desc(desc) {}

void TestSuite::init() {}

void TestSuite::deinit() {}

void TestSuite::Log(const char* format, ...) {
  va_list args;
  va_start(args, format);
  logs.push_back(format_str(format, args));
}

void TestSuite::Error(const char* format, ...) {
  va_list args;
  va_start(args, format);
  logs.push_back(format_str(format, args));
  had_errors = true;
}

Test& TestSuite::RegisterTest(Test test) {
  tests.push_back(test);
  return tests.back();
}

void TestSuite::AssertLogs(bool fail_if_no_expected) {
  std::string filename = class_name + "_" + current_test->func_name + ".txt";

  try {
    std::ifstream input_file(std::string("test/artifacts/expected_results/") +
                             filename);
    if (input_file.fail()) {
      if (fail_if_no_expected)
        throw ExpKitError("expected results file for test %s is missing",
                          filename.c_str());
      return;
    }

    int i = 0;
    std::string line;
    for (; std::getline(input_file, line); i++) {
      if (i >= logs.size())
        throw ExpKitError("expected more lines than %u", logs.size());
      if (line.compare(logs[i]))
        throw ExpKitError("expected '%s' but got '%s' for test log %s line %u",
                          line.c_str(), logs[i].c_str(), filename.c_str(),
                          i + 1);
    }

    if (i + 1 < logs.size())
      throw ExpKitError("expected %u lines but got %u", i + 1, logs.size());
  } catch (const std::exception& e) {
    write_file(std::string("test/artifacts/actual_results/") + filename,
               str_concat("\n", logs));
    throw;
  }
}

void TestSuite::AssertNoErrors() {
  if (had_errors) throw ExpKitError("the test failed with errors");
}
