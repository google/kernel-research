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

#include <cstdio>
#include <xdk/xdk_device/xdk_device.h>
#include "target/KxdbParser.h"
#include "test/TestSuite.h"
#include "test/TestUtils.h"
#include "util/file.h"

class SymbolsTest: public TestSuite {
public:
    SymbolsTest(): TestSuite("SymbolsRuntimeTests", "xdk db symbols tests") { }

    TEST_METHOD(symbolsCheck, "check if the database contains the correct symbols") {
        auto kaslr_base = env->GetXdkDevice().KaslrLeak();

        for (auto pair : env->GetTarget().GetAllSymbols()) {
            auto sym_addr = env->GetXdkDevice().SymAddrOpt(pair.first.c_str());

            // releases without CONFIG_KALLSYMS_ALL only contain function addresses
            if (sym_addr.has_value())
                TestUtils::eq(sym_addr.value() - kaslr_base, pair.second, pair.first.c_str());
        }
    }
};
