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

#include <cstring>
#include "util/error.cpp"

#define ASSERT_EQ(expected, actual) TestUtils::eq(expected, actual, #actual)
#define ASSERT_MINMAX(min, max, actual) TestUtils::minmax(min, max, actual, #actual)

struct TestUtils {
    template <class T, class T2>
    static void eq(T expected, T2 actual, const char* name) {
        if (expected != actual)
            throw ExpKitError("expected 0x%llx but got 0x%llx for %s", expected, actual, name);
    }

    static void eq(const char* expected, const char* actual, const char* name) {
        if (strcmp(expected, actual))
            throw ExpKitError("expected '%s' but got '%s' for %s", expected, actual, name);
    }

    template <class T>
    static void minmax(T min, T max, T actual, const char* name) {
        if (!(min <= actual && actual <= max))
            throw ExpKitError("expected %s to be between 0x%llx and 0x%llx, but got 0x%llx", name, min, max, actual);
    }
};
