#pragma once

#include <system_error>
#include <stdexcept>
#include <cstdarg>
#include "util/str.cpp"

struct ExpKitError : public std::runtime_error {
    template <typename... Args>
    ExpKitError(const char* error_msg) : std::runtime_error(error_msg) { }

    template <typename... Args>
    ExpKitError(const char* format, const Args&... args) : std::runtime_error(format_str(format, args...)) { }
};

struct errno_error: std::system_error {
    errno_error(): std::system_error(errno, std::generic_category()) { }
    errno_error(const char* __what): std::system_error(errno, std::generic_category(), __what) { }
};
