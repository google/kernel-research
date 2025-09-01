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

#include <iostream>
#include <memory>
#include <vector>
#include "test/logging/TestLogger.h"

using namespace std;

class TapLogger: public TestLogger {
public:
    void Begin(const vector<unique_ptr<TestSuite>>& test_suites, uint test_count);

    void End();

    void TestSuiteBegin(const TestSuite& suite);

    void TestSuiteFail(const TestSuite& suite, const std::exception& exc);

    void TestSuiteSkip(const TestSuite& suite, uint first_test_idx);

    void TestSuiteEnd(const TestSuite& suite);

    void TestBegin(const TestSuite& suite, const Test& test, uint test_idx);

    void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx);

    void TestFail(const TestSuite& suite, const Test& test, uint test_idx,
                const exception& exc);

    void TestSkip(const TestSuite& suite, const Test& test, uint test_idx);
};
