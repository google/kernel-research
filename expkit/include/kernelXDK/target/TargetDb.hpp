#pragma once

#include <map>
#include <memory>
#include <optional>
#include <vector>
#include <kernelXDK/target/Target.hpp>

class KpwnParser;

class TargetDb {
    std::unique_ptr<KpwnParser> parser_;

    std::vector<Target> static_targets_;
    std::map<std::string, size_t> by_version_;
    std::map<std::string, size_t> by_distro_release_;

    /**
     * @brief Merges data from a source Target object into a destination Target object.
     * @param dst The destination Target object to merge into.
     * @param src The source Target object to merge from.
     */
    void MergeTargets(Target& dst, const Target& src);

    /**
     * @brief Retrieves a Target object, merging data from a KpwnParser target and a static target if available.
     * @param target_opt An optional Target object parsed from a Kpwn file.
     * @param static_idx An optional index of a static target to merge.
     * @return The merged Target object.
     * @throws ExpKitError if both target_opt and static_idx are not provided.
     */
    Target GetTarget(std::optional<Target> target_opt,
                     std::optional<size_t> static_idx);

   public:
    // declare destructor
    ~TargetDb();
    TargetDb() = default;

    /**
     * @brief Constructs a TargetDb object.
     * @param filename A database file to read from.
     */
    TargetDb(const std::string &filename);

    /**
     * @brief Constructs a TargetDb object from a byte buffer.
     * @param buffer The buffer containing the Kpwn file data.
     * @param size The size of the buffer.
     */
    TargetDb(const uint8_t* buffer, size_t size);

    /**
     * @brief Adds a static target to the database.
     * @param target The static target to add.
     */
    void AddStaticTarget(const StaticTarget& target);

    /**
     * @brief Retrieves a Target object by distro and release name.
     * @param distro The distribution name.
     * @param release_name The release name.
     * @return The Target object.
     */
    Target GetTarget(const std::string& distro,
                     const std::string& release_name);

    /**
     * @brief Retrieves a Target object by version.
     * @param version The version string.
     * @return The Target object.
     */
    Target GetTarget(const std::string& version);

    /**
     * @brief Automatically detects the target based on the system's kernel version.
     * @return The detected Target object.
     * @throws ExpKitError if the target cannot be detected.
     */
    Target AutoDetectTarget();
};
