/*
 * Copyright 2026 Google LLC
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
#include <xdk/util/pwn_utils.h>

#include "test/TestSuite.h"
#include "test/TestUtils.h"

class UtilsRuntimeTests : public TestSuite {
    XdkDevice *xdk_;

public:
    UtilsRuntimeTests() : TestSuite("UtilsRuntimeTests", "pwn utils runtime tests") {}

    void init() { xdk_ = &env->GetXdkDevice(); }

    TEST_METHOD(leaksKaslrBase, "leaks KASLR base") {
        uint64_t page_count = env->GetTarget().GetKernelPageCount();
        uint64_t expected = xdk_->KaslrLeak();
        int wrong = 0;
        for (int i = 0; i < 100; i++) {
            uint64_t actual = leak_kaslr_base(page_count, /* samples = */ 100, /* trials = */ 3);
            if (actual != expected) {
                wrong++;
            }
        }
        ASSERT_MINMAX(0, 2, wrong);
    }
};
