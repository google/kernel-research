/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <algorithm>
#include <optional>
#include <vector>
#include <functional>

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
