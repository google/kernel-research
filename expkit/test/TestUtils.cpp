#pragma once

#include <cstring>
#include "util/error.cpp"

#define ASSERT_EQ(expected, actual) TestUtils::eq(expected, actual, #actual)
#define ASSERT_MINMAX(min, max, actual) TestUtils::minmax(min, max, actual, #actual)

struct TestUtils {
    /**
     * @brief Asserts that two values are equal.
     * 
     * @tparam T The type of the expected value.
     * @tparam T2 The type of the actual value.
     * @param expected The expected value.
     * @param actual The actual value.
     * @param name The name of the value being tested.
     */
    template <class T, class T2>
    static void eq(T expected, T2 actual, const char* name) {
        if (expected != actual)
            throw ExpKitError("expected 0x%llx but got 0x%llx for %s", expected, actual, name);
    }

    /**
     * @brief Asserts that two C-style strings are equal.
     * 
     * @param expected The expected string.
     * @param actual The actual string.
     * @param name The name of the string being tested.
     * @throws ExpKitError If the strings are not equal.
     */
    static void eq(const char* expected, const char* actual, const char* name) {
        if (strcmp(expected, actual))
            throw ExpKitError("expected '%s' but got '%s' for %s", expected, actual, name);
    }

    /**
     * @brief Asserts that a value is within a specified range.
     * 
     * @tparam T The type of the values.
     * @param min The minimum expected value.
     * @param max The maximum expected value.
     */
    template <class T>
    static void minmax(T min, T max, T actual, const char* name) {
        if (!(min <= actual && actual <= max))
            throw ExpKitError("expected %s to be between 0x%llx and 0x%llx, but got 0x%llx", name, min, max, actual);
    }
};