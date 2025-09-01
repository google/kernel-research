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
#include <xdk/target/TargetDb.h>
#include <xdk/xdk_device/xdk_device.h>

class TestEnvironment {
    std::string target_db_path_;
    std::optional<XdkDevice> xdk_;
    std::optional<TargetDb> target_db_;
    std::optional<Target> target_;

public:
    /**
     * @brief Sets the path to the target database file.
     * @param target_db_path The path to the target database.
     */
    void SetTargetDbPath(const std::string& target_db_path);

    /**
     * @brief Gets the XdkDevice instance.
     * @return A reference to the XdkDevice instance.
     * @throws ExpKitError if the xdk kernel module is not available.
     */
    XdkDevice& GetXdkDevice();

    /**
     * @brief Gets the Target database instance (which contains all the information
     * of the targets).
     * @return A reference to the TargetDb instance.
     * @throws ExpKitError if the target db path was not specified.
     */
    TargetDb& GetTargetDb();

    /**
     * @brief Gets the automatically detected Target instance.
     * @return A reference to the Target instance.
     * @throws ExpKitError if auto-detection fails or the target DB path is not
     * set.
     */
    Target& GetTarget();
};
