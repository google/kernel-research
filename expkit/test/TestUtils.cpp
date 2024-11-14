#pragma once

#include <cstdint>
#include "util/error.cpp"

struct TestUtils {
    static void eq(uint64_t expected, uint64_t actual, const char* name) {
        if (expected != actual)
            throw ExpKitError("expected 0x%llx but got 0x%llx for %s", expected, actual, name);
    }
};