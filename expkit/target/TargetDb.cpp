#pragma once

#include <optional>
#include "target/KpwnParser.cpp"
#include "util/stdutils.cpp"

class TargetDb {
    std::optional<KpwnParser> parser_;

    std::vector<Target> static_targets_;
    std::map<std::string, size_t> by_version_;
    std::map<std::string, size_t> by_distro_release_;

    /**
     * @brief Merges data from a source Target object into a destination Target object.
     * @param dst The destination Target object to merge into.
     * @param src The source Target object to merge from.
     */
    void MergeTargets(Target& dst, const Target& src) {
        if (!src.distro.empty())
            dst.distro = src.distro;
        if (!src.release_name.empty())
            dst.release_name = src.release_name;
        if (!src.version.empty())
            dst.version = src.version;

        dst.symbols.insert(src.symbols.begin(), src.symbols.end());
        dst.rop_actions.insert(src.rop_actions.begin(), src.rop_actions.end());

        dst.pivots.one_gadgets.insert(dst.pivots.one_gadgets.end(), src.pivots.one_gadgets.begin(), src.pivots.one_gadgets.end());
        dst.pivots.push_indirects.insert(dst.pivots.push_indirects.end(), src.pivots.push_indirects.begin(), src.pivots.push_indirects.end());
        dst.pivots.pop_rsps.insert(dst.pivots.pop_rsps.end(), src.pivots.pop_rsps.begin(), src.pivots.pop_rsps.end());
        dst.pivots.stack_shifts.insert(dst.pivots.stack_shifts.end(), src.pivots.stack_shifts.begin(), src.pivots.stack_shifts.end());

        for (const auto& [name, str] : src.structs) {
            if (dst.structs.find(name) == dst.structs.end()) {
                dst.structs[name] = str;
            } else {
                dst.structs[name].fields.insert(str.fields.begin(), str.fields.end());
            }
        }
    }

    /**
     * @brief Retrieves a Target object, merging data from a KpwnParser target and a static target if available.
     * @param target_opt An optional Target object parsed from a Kpwn file.
     * @param static_idx An optional index of a static target to merge.
     * @return The merged Target object.
     * @throws ExpKitError if both target_opt and static_idx are not provided.
     */
    Target GetTarget(std::optional<Target> target_opt, std::optional<size_t> static_idx) {
        Target target = target_opt.value_or(Target());
        if (static_idx.has_value())
            MergeTargets(target, static_targets_.at(static_idx.value()));
        return target;
    }

public:
    /**
     * @brief Constructs a TargetDb object.
     * @param parser An optional KpwnParser object to read target data from a Kpwn file.
     */
    TargetDb(std::optional<KpwnParser> parser = std::nullopt) : parser_(parser) { }
    
    /**
     * @brief Constructs a TargetDb object from a byte buffer.
     * @param buffer The buffer containing the Kpwn file data.
     * @param size The size of the buffer.
     */
    TargetDb(const uint8_t* buffer, size_t size): parser_(KpwnParser(buffer, size)) { }

    /**
     * @brief Adds a static target to the database.
     * @param target The static target to add.
     */
    void AddStaticTarget(const StaticTarget& target) {
        if (!target.version.empty())
            by_version_[target.version] = static_targets_.size();

        if (!target.distro.empty() && !target.release_name.empty())
            by_distro_release_[target.distro + "/" + target.release_name] = static_targets_.size();

        static_targets_.push_back(target);
    }

    /**
     * @brief Retrieves a Target object by distro and release name.
     * @param distro The distribution name.
     * @param release_name The release name.
     * @return The Target object.
     */
    Target GetTarget(const std::string& distro, const std::string& release_name) {
        auto target = parser_.has_value() ? parser_.value().GetTarget(distro, release_name) : std::nullopt;
        auto static_idx = find_opt(by_distro_release_, distro + "/" + release_name);

        if (!static_idx.has_value() && !target.has_value())
            throw ExpKitError("Target not found: %s/%s", distro.c_str(), release_name.c_str());

        if (!static_idx.has_value())
            static_idx = find_opt(by_version_, target.value().version);

        return GetTarget(target, static_idx);
    }

    /**
     * @brief Retrieves a Target object by version.
     * @param version The version string.
     * @return The Target object.
     */
    Target GetTarget(const std::string& version) {
        auto target = parser_.has_value() ? parser_.value().GetTarget(version) : std::nullopt;
        auto static_idx = find_opt(by_version_, version);

        if (!static_idx.has_value() && !target.has_value())
            throw ExpKitError("Target not found: %s", version.c_str());

        if (!static_idx.has_value())
            static_idx = find_opt(by_distro_release_, target.value().distro + "/" + target.value().release_name);

        return GetTarget(target, static_idx);
    }

    /**
     * @brief Automatically detects the target based on the system's kernel version.
     * @return The detected Target object.
     * @throws ExpKitError if the target cannot be detected.
     */
    Target AutoDetectTarget() {
        auto version_bytes = read_file("/proc/version");
        std::string version(version_bytes.begin(), version_bytes.end() - 1);
        return GetTarget(version);
    }
};
