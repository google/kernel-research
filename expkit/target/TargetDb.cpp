#include <optional>
#include "target/TargetDb.hpp"
#include "util/error.hpp"
#include "util/file.hpp"
#include "util/stdutils.hpp"

Target TargetDb::AutoDetectTarget() {
  auto version_bytes = read_file("/proc/version");
  std::string version(version_bytes.begin(), version_bytes.end() - 1);
  return GetTarget(version);
}

Target TargetDb::GetTarget(const std::string& version) {
  auto target =
      parser_.has_value() ? parser_.value().GetTarget(version) : std::nullopt;
  auto static_idx = find_opt(by_version_, version);

  if (!static_idx.has_value() && !target.has_value())
    throw ExpKitError("Target not found: %s", version.c_str());

  if (!static_idx.has_value())
    static_idx = find_opt(by_distro_release_, target.value().distro + "/" +
                                                  target.value().release_name);

  return GetTarget(target, static_idx);
}

Target TargetDb::GetTarget(const std::string& distro,
                           const std::string& release_name) {
  auto target = parser_.has_value()
                    ? parser_.value().GetTarget(distro, release_name)
                    : std::nullopt;
  auto static_idx = find_opt(by_distro_release_, distro + "/" + release_name);

  if (!static_idx.has_value() && !target.has_value())
    throw ExpKitError("Target not found: %s/%s", distro.c_str(),
                      release_name.c_str());

  if (!static_idx.has_value())
    static_idx = find_opt(by_version_, target.value().version);

  return GetTarget(target, static_idx);
}

void TargetDb::AddStaticTarget(const StaticTarget& target) {
  if (!target.version.empty())
    by_version_[target.version] = static_targets_.size();

  if (!target.distro.empty() && !target.release_name.empty())
    by_distro_release_[target.distro + "/" + target.release_name] =
        static_targets_.size();

  static_targets_.push_back(target);
}

TargetDb::TargetDb(const uint8_t* buffer, size_t size)
    : parser_(KpwnParser(buffer, size)) {}

TargetDb::TargetDb(std::optional<KpwnParser> parser) : parser_(parser) {}

Target TargetDb::GetTarget(std::optional<Target> target_opt,
                           std::optional<size_t> static_idx) {
  Target target = target_opt.value_or(Target());
  if (static_idx.has_value())
    MergeTargets(target, static_targets_.at(static_idx.value()));
  return target;
}

void TargetDb::MergeTargets(Target& dst, const Target& src) {
  if (!src.distro.empty()) dst.distro = src.distro;
  if (!src.release_name.empty()) dst.release_name = src.release_name;
  if (!src.version.empty()) dst.version = src.version;

  dst.symbols.insert(src.symbols.begin(), src.symbols.end());
  dst.rop_actions.insert(src.rop_actions.begin(), src.rop_actions.end());

  dst.pivots.one_gadgets.insert(dst.pivots.one_gadgets.end(),
                                src.pivots.one_gadgets.begin(),
                                src.pivots.one_gadgets.end());
  dst.pivots.push_indirects.insert(dst.pivots.push_indirects.end(),
                                   src.pivots.push_indirects.begin(),
                                   src.pivots.push_indirects.end());
  dst.pivots.pop_rsps.insert(dst.pivots.pop_rsps.end(),
                             src.pivots.pop_rsps.begin(),
                             src.pivots.pop_rsps.end());
  dst.pivots.stack_shifts.insert(dst.pivots.stack_shifts.end(),
                                 src.pivots.stack_shifts.begin(),
                                 src.pivots.stack_shifts.end());

  for (const auto& [name, str] : src.structs) {
    if (dst.structs.find(name) == dst.structs.end()) {
      dst.structs[name] = str;
    } else {
      dst.structs[name].fields.insert(str.fields.begin(), str.fields.end());
    }
  }
}
