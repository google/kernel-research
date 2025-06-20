#pragma once

#include <optional>
#include "target/KpwnParser.hpp"
#include "target/TargetDb.hpp"
#include "test/kpwn/Kpwn.cpp"
#include "util/file.cpp"

class TestEnvironment {
    std::string target_db_path_;
    std::optional<Kpwn> kpwn_;
    std::optional<TargetDb> target_db_;
    std::optional<Target> target_;

public:
    /**
     * @brief Sets the path to the target database file.
     * @param target_db_path The path to the target database.
     */
    void SetTargetDbPath(const std::string& target_db_path) {
        target_db_path_ = target_db_path;
    }

    /**
     * @brief Gets the Kpwn instance.
     * @return A reference to the Kpwn instance.
     * @throws ExpKitError if the kpwn kernel module is not available.
     */
    Kpwn& GetKpwn() {
        if (!Kpwn::IsAvailable())
            throw ExpKitError("the kpwn kernel module is not available");

        if (!kpwn_.has_value())
            kpwn_.emplace();

        return kpwn_.value();
    }

    /**
     * @brief Gets the Target database instance (which contains all the information of the targets).
     * @return A reference to the TargetDb instance.
     * @throws ExpKitError if the target db path was not specified.
     */
    TargetDb& GetTargetDb() {
        if (target_db_path_.empty())
            throw ExpKitError("the target db path was not specified in the environment");

        if (!target_db_)
        target_db_ = TargetDb(KpwnParser(read_file(target_db_path_.c_str())));
        return target_db_.value();
    }

    /**
     * @brief Gets the automatically detected Target instance.
     * @return A reference to the Target instance.
     * @throws ExpKitError if auto-detection fails or the target DB path is not set.
     */
    Target& GetTarget() {
        if (!target_)
            target_ = GetTargetDb().AutoDetectTarget();
        return target_.value();
    }
};