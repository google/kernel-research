#pragma once

/**
 * @brief Aligns a number to the nearest multiple of the given alignment.
 * @tparam T The type of the number and alignment.
 * @param number The number to align.
 * @param alignment The alignment value.
 * @return The aligned number.
 */
template <typename T>
T align(T number, T alignment);