#include <system_error>
#include <stdexcept>
#include <cstdarg>
#include "util/str.hpp"
#include "util/error.hpp"

errno_error::errno_error()
    : std::system_error(errno, std::generic_category()) {}

errno_error::errno_error(const char* __what)
    : std::system_error(errno, std::generic_category(), __what) {}
