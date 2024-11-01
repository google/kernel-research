#pragma once

#include <cstring>
#include "util/error.cpp"

#define ASSERT_EQ(expected, actual) TestUtils::eq(expected, actual, #actual)

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
};