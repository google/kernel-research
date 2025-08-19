#include <system_error>
#include <stdexcept>
#include <cstdarg>
#include <kernelXDK/util/error.h>

errno_error::errno_error()
    : std::system_error(errno, std::generic_category()) {}

errno_error::errno_error(const char* __what)
    : std::system_error(errno, std::generic_category(), __what) {}
