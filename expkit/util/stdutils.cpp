#pragma once

#include <algorithm>
#include <optional>
#include <vector>
#include <functional>
#include "util/stdutils.hpp"

template <typename T, typename T2>
bool contains(const std::vector<T>& vec, const T2& value) {
    return std::find(vec.begin(), vec.end(), value) != vec.end();
}

template <typename T>
void sortByField(std::vector<T>& vec, std::function<int64_t(const T&)> fieldGetter) {
    std::sort(vec.begin(), vec.end(), [&fieldGetter](const T& obj1, const T& obj2) {
        return fieldGetter(obj1) < fieldGetter(obj2);
    });
}

template <typename Map, typename Key>
std::optional<typename Map::mapped_type> find_opt(const Map& m, const Key& k) {
    auto it = m.find(k);
    return it != m.end() ? std::optional(it->second) : std::nullopt;
}