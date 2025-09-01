// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test/logging/TestLogger.h"
#include "test/TestRunner.h"

#include <xdk/util/str.h>

#include <memory>
#include <optional>
#include <vector>

void ConditionMatcher::SetFilter(const optional<string>& filter_expression) {
  filter_.clear();
  if (!filter_expression.has_value()) return;

  for (auto& cond_expr : split(filter_expression.value(), ",")) {
    vector<TextFilter> conditions;
    for (auto& label : split(cond_expr, "+")) {
      if (startsWith(label, "^"))
        conditions.push_back(TextFilter{true, label.substr(1)});
      else
        conditions.push_back(TextFilter{false, label});
    }
    filter_.push_back(conditions);
  }
}

bool ConditionMatcher::Match(const string& raw, const string& as_label) {
  if (filter_.empty()) return true;

  for (auto& filter : filter_) {
    bool match = true;
    for (auto& lf : filter) {
      bool found =
          contains(raw, lf.text) || contains(as_label, "[" + lf.text + "]");
      match &= lf.must_not_exist ? !found : found;
      if (!match) break;
    }
    if (match) return true;
  }

  return false;
}

TestRunner::TestRunner() : logger_(new PrintfLogger()) {}

void TestRunner::Add(TestSuite* suite) {
  suite->env = &environment;
  test_suites_.push_back(unique_ptr<TestSuite>(suite));
}

void TestRunner::SetSuiteFilter(optional<string> filter) {
  test_suite_filter_.SetFilter(filter);
}

void TestRunner::SetTestFilter(optional<string> filter) {
  test_filter_.SetFilter(filter);
}

void TestRunner::SetTargetDbPath(const std::string& target_db_path) {
  environment.SetTargetDbPath(target_db_path);
}

void TestRunner::SetRepeatCount(uint repeat_count) {
  repeat_count_ = repeat_count;
}

const std::vector<unique_ptr<TestSuite>>& TestRunner::GetTestSuites() {
  return test_suites_;
}

bool TestRunner::Run(uint skip) {
  bool success = true;

  uint test_idx = 0;
  uint test_count = 0;
  for (auto& testSuite : test_suites_) test_count += testSuite->tests.size();

  logger_->Begin(test_suites_, test_count);
  for (auto& testSuite : test_suites_) {
    if (ShouldSkipSuite(*testSuite)) {
      logger_->TestSuiteSkip(*testSuite, test_idx);
      test_idx += testSuite->tests.size();
      continue;
    }

    logger_->TestSuiteBegin(*testSuite);
    try {
      testSuite->init();
    } catch (const exception& exc) {
      logger_->TestSuiteFail(*testSuite, exc);
      test_idx += testSuite->tests.size();
      success = false;
      continue;
    }

    for (auto& test : testSuite->tests) {
      if (skip > test_idx || ShouldSkipTest(test)) {
        logger_->TestSkip(*testSuite, test, test_idx++);
        continue;
      }

      testSuite->current_test = &test;
      testSuite->logs.clear();
      testSuite->had_errors = false;
      logger_->TestBegin(*testSuite, test, test_idx);
      try {
        for (int repeat_id = 0; repeat_id < repeat_count_; repeat_id++)
          test.func();
        testSuite->AssertLogs(false);
        testSuite->AssertNoErrors();
        logger_->TestSuccess(*testSuite, test, test_idx);
      } catch (const exception& exc) {
        success = false;
        logger_->TestFail(*testSuite, test, test_idx, exc);
      }
      testSuite->current_test = nullptr;
      test_idx++;
    }
    testSuite->deinit();
    logger_->TestSuiteEnd(*testSuite);
  }

  logger_->End();
  return success;
}

void TestRunner::SetLogger(TestLogger* logger) { logger_.reset(logger); }
