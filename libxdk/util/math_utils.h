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

/**
 * @brief Aligns a number to the nearest multiple of the given alignment.
 * @tparam T The type of the number and alignment.
 * @param number The number to align.
 * @param alignment The alignment value.
 * @return The aligned number.
 */
template <typename T>
T align(T number, T alignment) {
    return (number + alignment - 1) & ~(alignment - 1);
}