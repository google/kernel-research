cmake_minimum_required(VERSION 3.15)

project(kernelXDK
    VERSION 1.0.0
    LANGUAGES CXX
)

# --- Compiler Configuration ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /EHsc /permissive-)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded$<$<CONFIG:Debug>:Debug>)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fPIC)
endif()

# --- Source File Collection for the Library ---
# This remains the same, as your .cpp files are still in these directories.
set(LIBRARY_SOURCE_ROOT_DIRS
    xdk_device
    rip
    target
    util
    pivot
    payloads
)

set(KERNELXDK_SRCS "")
foreach(DIR ${LIBRARY_SOURCE_ROOT_DIRS})
    file(GLOB_RECURSE CURRENT_DIR_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/${DIR}/*.cpp")
    list(APPEND KERNELXDK_SRCS ${CURRENT_DIR_SRCS})
endforeach()

add_library(${PROJECT_NAME} STATIC ${KERNELXDK_SRCS})

# --- Define Include Directories ---
target_include_directories(kernelXDK
    # PUBLIC: For consumers of the library.
    # They will find public headers in <kernelXDK/...>
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>

    # PRIVATE: For building the library itself.
    # This allows your internal .cpp files to find private headers
    # like "util/str.h" that are in the source tree.
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# --- Simplified Public Header Installation ---
# This replaces the entire KERNELXDK_PUBLIC_HEADERS list and the complex loop.
# It tells CMake to take the 'kernelXDK' directory from inside your local 'include'
# directory and install it to the destination 'include' directory.
# This preserves the entire subdirectory structure (e.g., kernelXDK/target, kernelXDK/util).
install(DIRECTORY include/kernelXDK
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# --- Installation for the Library Itself (static .lib/.a file) ---
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets
    ARCHIVE DESTINATION lib
)

# --- Installation of cmake components ---
install(EXPORT ${PROJECT_NAME}Targets
  FILE        ${PROJECT_NAME}Targets.cmake
  NAMESPACE   ${PROJECT_NAME}::
  DESTINATION "lib/cmake/${PROJECT_NAME}"
)

# --- Generate CMake Package Configuration Files ---
# This part remains the same.
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

# Assuming you have this file in a 'cmake' subdirectory
configure_package_config_file(
    "cmake/${PROJECT_NAME}Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION "lib/cmake/${PROJECT_NAME}"
)

# --- Add Subdirectories for Tests and Samples ---
enable_testing()
add_subdirectory(test)
add_subdirectory(samples)
