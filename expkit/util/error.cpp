#pragma once

#include <stdexcept>
#include <cstdarg>
#include "util/str.cpp"

struct ExpKitError : public std::runtime_error {
    template <typename... Args>
    ExpKitError(const char* format, const Args&... args) : std::runtime_error(format_str(format, args...)) { }
};
