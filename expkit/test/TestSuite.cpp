#pragma once

#include <functional>
#include <string>
#include <vector>
#include "test/TestEnvironment.cpp"
#include "util/log.cpp"
#include "util/str.cpp"

#define TEST_METHOD(name, desc) \
    Test _test_ ## name = registerTest(Test(#name, desc, [this]() { name(); })); \
    void name()

struct Test {
    std::string func_name;
    std::string desc;
    std::function<void()> func;

    Test(std::string func_name, std::string desc, std::function<void()> func): func_name(func_name), desc(desc), func(func) { }
};

struct TestSuite: ILog {
    std::string class_name;
    std::string desc;
    std::vector<Test> tests;
    std::vector<std::string> logs;
    TestEnvironment* env;

    TestSuite() {}
    TestSuite(std::string class_name, std::string desc): class_name(class_name), desc(desc) { }

    virtual void init() { }
    virtual void deinit() { }

    void log(LogLevel log_level, const char* format, ...) {
        va_list args;
        va_start(args, format);
        logs.push_back(format_str(format, args));
    }

    Test& registerTest(Test test) {
        tests.push_back(test);
        return tests.back();
    }
};