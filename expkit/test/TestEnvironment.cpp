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

#include <optional>
#include "target/KpwnParser.cpp"
#include "target/TargetDb.cpp"
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
