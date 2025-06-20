#pragma once

#include <system_error>
#include <stdexcept>
#include <cstdarg>
#include "util/str.hpp"
#include "util/error.hpp"

template <typename... Args>
ExpKitError::ExpKitError(const char* error_msg)
    : std::runtime_error(error_msg) {}

template <typename... Args>
ExpKitError::ExpKitError(const char* format, const Args&... args)
    : std::runtime_error(format_str(format, args...)) {}

errno_error::errno_error()
    : std::system_error(errno, std::generic_category()) {}

errno_error::errno_error(const char* __what)
    : std::system_error(errno, std::generic_category(), __what) {}
