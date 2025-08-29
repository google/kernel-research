#include <filesystem>
#include <memory>
#include <optional>
#include <xdk/target/TargetDb.h>
#include <xdk/util/error.h>
#include "target/KxdbParser.h"
#include "util/file.h"
#include "util/stdutils.h"

Target TargetDb::AutoDetectTarget() {
  auto version_bytes = read_file("/proc/version");
  std::string version(version_bytes.begin(), version_bytes.end() - 1);
  return GetTarget(version);
}

Target TargetDb::GetTarget(const std::string& version) {
  auto target =
      parser_ ? parser_->GetTarget(version) : std::nullopt;
  auto static_idx = find_opt(by_version_, version);

  if (!static_idx.has_value() && !target.has_value())
    throw ExpKitError("Target not found: %s", version.c_str());

  if (!static_idx.has_value())
    static_idx = find_opt(by_distro_release_, target.value().GetDistro() + "/" +
                                                  target.value().GetReleaseName());

  return GetTarget(target, static_idx);
}

// define destructor here so it has access to KxdbParser.h
TargetDb::~TargetDb() = default;

Target TargetDb::GetTarget(const std::string& distro,
                           const std::string& release_name) {
  auto target = parser_
                    ? parser_->GetTarget(distro, release_name)
                    : std::nullopt;
  auto static_idx = find_opt(by_distro_release_, distro + "/" + release_name);

  if (!static_idx.has_value() && !target.has_value())
    throw ExpKitError("Target not found: %s/%s", distro.c_str(),
                      release_name.c_str());

  if (!static_idx.has_value())
    static_idx = find_opt(by_version_, target.value().GetVersion());

  return GetTarget(target, static_idx);
}

void TargetDb::AddTarget(const Target& target) {
  if (!target.GetVersion().empty())
    by_version_[target.GetVersion()] = static_targets_.size();

  if (!target.GetDistro().empty() && !target.GetReleaseName().empty())
    by_distro_release_[target.GetDistro() + "/" + target.GetReleaseName()] =
        static_targets_.size();

  static_targets_.push_back(target);
}

TargetDb::TargetDb(const std::string &filename) {
  parser_ = std::make_unique<KxdbParser>(KxdbParser::FromFile(filename));
}

TargetDb::TargetDb(const std::vector<uint8_t>& data)
    : parser_(std::make_unique<KxdbParser>(data)) {}

TargetDb::TargetDb(const std::string &filename, const std::vector<uint8_t>& fallback_kxdb) {
  auto file_exists = std::filesystem::exists(filename);
  parser_ = std::make_unique<KxdbParser>(file_exists ? KxdbParser::FromFile(filename) : KxdbParser(fallback_kxdb));
}

Target TargetDb::GetTarget(std::optional<Target> target_opt,
                           std::optional<size_t> static_idx) {
  Target target = target_opt.value_or(Target("", ""));
  if (static_idx.has_value())
    target.Merge(static_targets_.at(static_idx.value()));
  return target;
}
