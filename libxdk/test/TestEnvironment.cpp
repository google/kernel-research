#include <kernelXDK/target/TargetDb.h>
#include <kernelXDK/util/error.h>
#include "test/TestEnvironment.h"
#include <kernelXDK/xdk_device/xdk_device.h>

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
