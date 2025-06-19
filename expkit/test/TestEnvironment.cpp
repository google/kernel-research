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
    void SetTargetDbPath(const std::string& target_db_path) {
        target_db_path_ = target_db_path;
    }

    Kpwn& GetKpwn() {
        if (!Kpwn::IsAvailable())
            throw ExpKitError("the kpwn kernel module is not available");

        if (!kpwn_.has_value())
            kpwn_.emplace();

        return kpwn_.value();
    }

    TargetDb& GetTargetDb() {
        if (target_db_path_.empty())
            throw ExpKitError("the target db path was not specified in the environment");

        if (!target_db_)
        target_db_ = TargetDb(KpwnParser(read_file(target_db_path_.c_str())));
        return target_db_.value();
    }

    Target& GetTarget() {
        if (!target_)
            target_ = GetTargetDb().AutoDetectTarget();
        return target_.value();
    }
};