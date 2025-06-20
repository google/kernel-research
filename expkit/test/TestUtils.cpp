#pragma once

#include <cstring>
#include "test/TestUtils.hpp"

template <class T, class T2>
void TestUtils::eq(T expected, T2 actual, const char* name) {
  if (expected != actual)
    throw ExpKitError("expected 0x%llx but got 0x%llx for %s", expected, actual,
                      name);
}

void TestUtils::eq(const char* expected, const char* actual, const char* name) {
  if (strcmp(expected, actual))
    throw ExpKitError("expected '%s' but got '%s' for %s", expected, actual,
                      name);
}

template <class T>
void TestUtils::minmax(T min, T max, T actual, const char* name) {
  if (!(min <= actual && actual <= max))
    throw ExpKitError(
        "expected %s to be between 0x%llx and 0x%llx, but got 0x%llx", name,
        min, max, actual);
}
