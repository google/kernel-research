#include <algorithm>
#include <cstdarg>
#include <string>
#include <vector>
#include <xdk/util/str.h>

std::string format_str(const char* format, va_list args) {
    std::va_list args_copy;
    va_copy(args_copy, args);
    int len = std::vsnprintf(nullptr, 0, format, args_copy);
    va_end(args_copy);

    std::string result(len, '\0');
    std::vsnprintf(result.data(), len + 1, format, args);
    va_end(args);
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

void replace(std::string& str, const std::string& from, const std::string& to) {
    std::string::size_type pos = 0u;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
}

void tolower(std::string& str) {
    std::transform(str.begin(), str.end(), str.begin(),
        [](unsigned char c){ return std::tolower(c); });
}

std::vector<std::string> split(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> results;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::string::npos) {
        results.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }

    results.push_back(str.substr(start));
    return results;
}

bool contains(const std::string& str, const std::string& pattern) {
    return str.find(pattern) != std::string::npos;
}

bool startsWith(const std::string& str, const std::string& prefix) {
    return str.compare(0, prefix.length(), prefix) == 0;
}