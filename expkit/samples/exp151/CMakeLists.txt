# samples/exp151/CMakeLists.txt
# This CMakeLists.txt is entirely self-contained for the exp151 sample.

cmake_minimum_required(VERSION 3.19) # Required for [[...]] syntax
project(exp151 LANGUAGES CXX)

# --- 1. Find the main kernelXDK library ---
# this is only needed outside this project
#find_package(kernelXDK CONFIG REQUIRED)

# --- 2. for external libraries use pkg-config
find_package(PkgConfig REQUIRED)

# Now, use pkg_check_modules to find libnl3 via its .pc files
# Common pkg-config names for libnl are 'libnl-3.0', 'libnl-nf-3.0', 'libnl-route-3.0'.
# We'll create an imported target 'PkgConfig::LIBNL3'
pkg_check_modules(LIBNL3 REQUIRED IMPORTED_TARGET libnl-3.0 libnl-nf-3.0 libnl-route-3.0)
# The 'REQUIRED' keyword here will cause CMake to error out if pkg-config cannot find them.


# --- 3. Define the executable ---
add_executable(exp151 exploit.cpp)

# --- 4. Link dependencies ---
target_link_libraries(exp151 PRIVATE kernelXDK)
target_link_libraries(exp151 PRIVATE PkgConfig::LIBNL3) 

# --- 5. Add include paths for sample-specific headers ---
target_include_directories(exp151 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# --- 6. Handle sample-specific data files (target_db.kpwn) ---
# Download target_db.kpwn directly to this sample's binary directory.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/target_db.kpwn
    COMMAND wget -O ${CMAKE_CURRENT_BINARY_DIR}/target_db.kpwn "https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kpwn"
    VERBATIM
)


# --- 7. Define 'run' custom target ---
add_custom_target(exp151_run
    # 1. Copy the executable into the current binary directory (as 'exp' as per Makefile)
    COMMAND cp "$<TARGET_FILE:exp151>" "${CMAKE_CURRENT_BINARY_DIR}/exp"
    # 2. Copy the sample's exp.sh script into the current binary directory
    COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/exp151/exp.sh" "${CMAKE_CURRENT_BINARY_DIR}/exp.sh"

    # 3. Execute the runner script from within the current binary directory
    COMMAND bash -c [[
        "${CMAKE_SOURCE_DIR}/kernel-image-runner/run.sh" \
        "kernelctf lts-6.1.79" \
        -- "./exp.sh" | tee "./output.txt"
    ]]
    
    # The 'run' target depends on the executable being built
    # AND explicitly on target_db.kpwn being downloaded/present.
    DEPENDS exp151 "${CMAKE_CURRENT_BINARY_DIR}/target_db.kpwn"

    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" # All commands will run from here
    COMMENT "Running sample exp151"
)

# --- 8. Define 'test' custom target ---
add_custom_target(exp151_test
    COMMAND echo "Running test for exp151"
    COMMAND cmake --build . --target exp151_run # Ensure the 'run' target is executed first
    COMMAND bash -c [[
        grep "CTF{secret_flag_deadbeef}" "./output.txt" || {
            echo "Failed to leak the flag."
            echo "dmesg content: "
            cat "./dmesg.txt"
            exit 1
        }
    ]]
    DEPENDS exp151_run
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Testing sample exp151"
)