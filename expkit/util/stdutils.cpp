#pragma once

#include <algorithm>
#include <vector>

template <typename T, typename T2>
bool contains(const std::vector<T>& vec, const T2& value) {
    return std::find(vec.begin(), vec.end(), value) != vec.end();
}
