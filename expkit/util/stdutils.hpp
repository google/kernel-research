#pragma once

#include <algorithm>
#include <optional>
#include <vector>
#include <functional>

/**
 * @brief Checks if a vector contains a given value.
 *
 * @tparam T The type of elements in the vector.
 * @tparam T2 The type of the value to search for.
 * @param vec The vector to search within.
 * @param value The value to search for.
 * @return True if the value is found in the vector, false otherwise.
 */
template <typename T, typename T2>
bool contains(const std::vector<T>& vec, const T2& value);

/**
 * @brief Sorts a vector based on a field accessed by a getter function.
 */
template <typename T>
void sortByField(std::vector<T>& vec, std::function<int64_t(const T&)> fieldGetter);

/**
 * @brief Finds a value in a map and returns it as an optional.
 *
 * @tparam Map The type of the map.
 * @tparam Key The type of the key.
 * @return An optional containing the value if the key is found, std::nullopt otherwise.
 */
template <typename Map, typename Key>
std::optional<typename Map::mapped_type> find_opt(const Map& m, const Key& k);