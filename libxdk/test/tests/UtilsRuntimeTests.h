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
#include <iostream>

class UtilsRuntimeTests: public TestSuite {
    XdkDevice* xdk_;
public:
    UtilsRuntimeTests(): TestSuite("UtilsRuntimeTests", "pwn utils runtime tests") { }

    void init() {
        xdk_ = &env->GetXdkDevice();
    }

    TEST_METHOD(leaksKaslrBase, "leaks KASLR base") {
        uint64_t expected = xdk_->KaslrLeak();

        int total = 1;
        int incorrect = 0;
        for (int i = 0; i < total; i++) {
            std::vector<std::vector<uint64_t>> debug_data;
            uint64_t actual = leak_kaslr_base(100, 51, &debug_data);
            if (actual != expected) {
               printf("Iteration: %d failed, expected %llx, got %llx\n", i, expected, actual);
               
               for (size_t trial = 0; trial < debug_data.size(); trial++) {
                   const auto& timings = debug_data[trial];
                   printf("Trial %lu timings:\n", trial);
                   for (size_t slot = 0; slot < timings.size(); slot++) {
                       printf("Slot %lx: %lu\n", 0xffffffff81000000 + slot * 0x200000, timings[slot]);
                   }
               }
               
               incorrect++;
            }
        }
        ASSERT_EQ(0, incorrect);
    }
};
