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

#include <memory>
#include <vector>
#include "test/TestSuite.h"

class TestLogger {
public:
    virtual void Begin(const std::vector<std::unique_ptr<TestSuite>>& test_suites, uint test_count) = 0;
    virtual void End() = 0;
    virtual void TestSuiteBegin(const TestSuite& suite) = 0;
    virtual void TestSuiteEnd(const TestSuite& suite) = 0;
    virtual void TestSuiteSkip(const TestSuite& suite, uint first_test_idx) = 0;
    virtual void TestSuiteFail(const TestSuite& suite, const std::exception& exc) = 0;
    virtual void TestSkip(const TestSuite& suite, const Test& test, uint test_idx) = 0;
    virtual void TestBegin(const TestSuite& suite, const Test& test, uint test_idx) = 0;
    virtual void TestSuccess(const TestSuite& suite, const Test& test, uint test_idx) = 0;
    virtual void TestFail(const TestSuite& suite, const Test& test, uint test_idx, const std::exception& exc) = 0;
};

