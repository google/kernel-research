cmake_minimum_required(VERSION 3.19) # Required for [[...]] syntax
project(exp151 LANGUAGES CXX)

# --- 1. Find the main kernelXDK library ---
# this is only needed outside this project
find_package(kernelXDK CONFIG REQUIRED)

get_target_property(INCLUDES kernelXDK::kernelXDK INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "kernelXDK includes found by CMake: ${INCLUDES}")


# --- 2. for external libraries use pkg-config
find_package(PkgConfig REQUIRED)

# Now, use pkg_check_modules to find libnl3
pkg_check_modules(LIBNL3 REQUIRED IMPORTED_TARGET libnl-3.0 libnl-nf-3.0 libnl-route-3.0)


# --- 3. Define the executable ---
add_executable(exp151 exploit.cpp)

# --- 4. Link dependencies ---
target_link_libraries(exp151 PRIVATE kernelXDK::kernelXDK)
target_link_libraries(exp151 PRIVATE PkgConfig::LIBNL3) 

# --- 5. Add include paths for sample-specific headers ---
target_include_directories(exp151 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# --- 6. Handle sample-specific data files (target_db.kxdb) ---
# Download target_db.kxdb directly to this sample's binary directory.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/target_db.kxdb
    COMMAND wget -O ${CMAKE_CURRENT_BINARY_DIR}/target_db.kxdb "https://storage.googleapis.com/kernel-research/pwnkit/db/kernelctf.kxdb"
    VERBATIM
)