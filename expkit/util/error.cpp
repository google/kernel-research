#pragma once

#include <system_error>
#include <stdexcept>
#include <cstdarg>
#include "util/str.cpp"

struct ExpKitError : public std::runtime_error {
    /**
     * @brief Constructs an ExpKitError with a single error message.
     * @param error_msg The error message.
     */
    template <typename... Args>
    ExpKitError(const char* error_msg) : std::runtime_error(error_msg) { }

    /**
     * @brief Constructs an ExpKitError with a formatted error message.
     * @tparam Args The types of the arguments for the format string.
     * @param format The format string.
     * @param args The arguments for the format string.
     */
    template <typename... Args>
    ExpKitError(const char* format, const Args&... args) : std::runtime_error(format_str(format, args...)) { }
};

/**
 * @brief Represents an error based on the current value of errno.
 */
struct errno_error: std::system_error {
    /**
     * @brief Constructs an errno_error with the current errno value.
     */
    errno_error(): std::system_error(errno, std::generic_category()) { }
    
    /**
     * @brief Constructs an errno_error with the current errno value and an additional message.
     * @param __what An additional message describing the error.
     */
    errno_error(const char* __what): std::system_error(errno, std::generic_category(), __what) { }
};
