#pragma once

#include <cstdarg>
#include <string>
#include <vector>

std::string format_str(const char* format, va_list args) {
    std::va_list args_copy;
    va_copy(args_copy, args);
    int len = std::vsnprintf(nullptr, 0, format, args_copy);
    va_end(args_copy);

    std::string result(len + 1, '\0');
    std::vsnprintf(result.data(), len + 1, format, args);
    va_end(args);
    return result;
}

template <typename... Args>
std::string format_str(const char* format, const Args&... args) {
    int buffer_size = std::snprintf(nullptr, 0, format, args...) + 1; // +1 for null terminator
    std::string result(buffer_size - 1, '\0');
    std::snprintf(result.data(), buffer_size, format, args...);
    return result;
}

std::string str_concat(const std::string& delimiter, const std::vector<std::string>& strings) {
    std::string result;
    for (size_t i = 0; i < strings.size(); i++) {
        if (i != 0)
            result.append(delimiter);
        result.append(strings[i]);
    }
    return result;
}

void replace(std::string& str, const std::string& from, const std::string& to)
{
    std::string::size_type pos = 0u;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
}