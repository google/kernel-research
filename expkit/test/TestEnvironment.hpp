#pragma once

#include <optional>
#include <kernelXDK/target/TargetDb.hpp>
#include "kpwn/Kpwn.hpp"

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
    void SetTargetDbPath(const std::string& target_db_path);

    /**
     * @brief Gets the Kpwn instance.
     * @return A reference to the Kpwn instance.
     * @throws ExpKitError if the kpwn kernel module is not available.
     */
    Kpwn& GetKpwn();

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
