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

#include <xdk/target/TargetDb.h>
#include <xdk/util/error.h>
#include "test/TestEnvironment.h"
#include <xdk/xdk_device/xdk_device.h>

void TestEnvironment::SetTargetDbPath(const std::string& target_db_path) {
  target_db_path_ = target_db_path;
}

XdkDevice& TestEnvironment::GetXdkDevice() {
  if (!XdkDevice::IsAvailable())
    throw ExpKitError("the xdk kernel module is not available");

  if (!xdk_.has_value()) xdk_.emplace();

  return xdk_.value();
}

TargetDb& TestEnvironment::GetTargetDb() {
  if (target_db_path_.empty())
    throw ExpKitError(
        "the target db path was not specified in the environment");

  if (!target_db_)
    target_db_.emplace(target_db_path_);
  return target_db_.value();
}

Target& TestEnvironment::GetTarget() {
  if (!target_) target_ = GetTargetDb().AutoDetectTarget();
  return target_.value();
}
