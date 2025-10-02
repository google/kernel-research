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

#include <sched.h>
#include "test/TestUtils.h"
#include "test/TestSuite.h"
#include <xdk/util/pwn_utils.h>

class UtilsTests: public TestSuite {
    cpu_set_t original_set_;
public:
    UtilsTests(): TestSuite("UtilsStaticTests", "pwn utils tests") { }

    void init() {
        if (sched_getaffinity(0, sizeof(original_set_), &original_set_)) {
            throw errno_error("sched_getaffinity failed");
        }
    }

    void deinit() {
        if (sched_setaffinity(0, sizeof(original_set_), &original_set_)) {
            throw errno_error("sched_setaffinity failed");
        }
    }

    TEST_METHOD(pinsToCpu0, "pins to CPU 0") {
        pin_cpu(0);

        cpu_set_t expected;
        CPU_ZERO(&expected);
        CPU_SET(0, &expected);
        cpu_set_t actual;
        if (sched_getaffinity(0, sizeof(actual), &actual))
            throw errno_error("sched_getaffinity failed");
        ASSERT_NE(0, CPU_EQUAL(&expected, &actual));
    }

    TEST_METHOD(pinsToInvalidCpuThrows, "pins to CPU -1 throws") {
        try {
            pin_cpu(-1);
            throw new ExpKitError("pin_cpu(-1) did not throw an exception");
        } catch(const errno_error &e) {
            ASSERT_EQ("sched_setaffinity failed: Invalid argument", e.what());
        }
    }
};
