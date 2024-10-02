#pragma once

#include <functional>
#include <string>
#include <vector>
#include "util/log.cpp"
#include "util/str.cpp"

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

    TestSuite() {}
    TestSuite(std::string class_name, std::string desc): class_name(class_name), desc(desc) { }

    void log(LogLevel log_level, const char* format, ...) {
        va_list args;
        va_start(args, format);
        logs.push_back(format_str(format, args));
    }
};