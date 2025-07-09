cmake_minimum_required(VERSION 3.15)

project(kernelXDK
    VERSION 1.0.0
    LANGUAGES CXX
)

# --- Compiler Configuration ---
set(CMAKE_CXX_STANDARD 17) # Or 20, or whatever C++ standard you use
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /EHsc /permissive-)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded$<$<CONFIG:Debug>:Debug>)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fPIC)
endif()

# --- Source File Collection for the Library ---
# List of directories containing your C++ source files
set(LIBRARY_SOURCE_ROOT_DIRS
    kpwn
    rip
    target
    util
    pivot
    payloads
)

# Collect all .cpp files from these directories
set(KERNELXDK_SRCS "")
foreach(DIR ${LIBRARY_SOURCE_ROOT_DIRS})
    file(GLOB_RECURSE CURRENT_DIR_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/${DIR}/*.cpp")
    list(APPEND KERNELXDK_SRCS ${CURRENT_DIR_SRCS})
endforeach()

add_library(${PROJECT_NAME} STATIC ${KERNELXDK_SRCS})


# --- Define Public Headers for Installation ---
# THIS IS THE MOST IMPORTANT PART FOR YOUR SCENARIO.
# You MUST explicitly list all header files that you want to be part of your
# publicly consumable API. These are the files users will #include.
#
# IMPORTANT: For each header, you specify its source path and its *desired*
# installation path relative to the 'include' directory (e.g., install/include/).
#
# The goal is that users can then do:
# #include <kernelXDK/kpwn/kpwn.h>
# #include <kernelXDK/rip/RopUtils.hpp> (if RopUtils.hpp is public)
# ...etc.

set(KERNELXDK_PUBLIC_HEADERS
    "kpwn/include/kpwn.h" # This header is in 'kpwn/include', but should install under 'kernelxdk/kpwn'
    "rip/RopUtils.hpp"
    "target/Target.hpp"
    "target/TargetDb.hpp"
    "target/KpwnParser.hpp"
    "target/BinaryReader.hpp"
    "util/log.hpp"
    "util/error.hpp"
    "util/file.hpp"
    "util/math_utils.hpp"
    "util/pwn_utils.hpp"
    "util/str.hpp"
    "util/syscalls.hpp"
    "util/stdutils.hpp"
    "util/incbin.hpp"
    "util/ArgumentParser.hpp"
    "util/HexDump.hpp"
    "util/Register.hpp"
    "pivot/Pivots.hpp"
    "pivot/PivotFinder.hpp"
    "pivot/StackPivot.hpp"
    "payloads/Payload.hpp"
    "payloads/PayloadBuilder.hpp"
    "payloads/RopChain.hpp"
    # Add any other public headers here
)

foreach(HEADER_PATH ${KERNELXDK_PUBLIC_HEADERS})
    set(MODULE_NAME "")
    # Find which root module directory this header belongs to
    foreach(MODULE_ROOT_DIR ${LIBRARY_SOURCE_ROOT_DIRS})
        if("${HEADER_PATH}" MATCHES "^${MODULE_ROOT_DIR}/")
            set(MODULE_NAME "${MODULE_ROOT_DIR}")
            break() # Found it, exit inner loop
        endif()
    endforeach()

    if(NOT MODULE_NAME)
        # This error means a header in KERNELXDK_PUBLIC_HEADERS doesn't start with
        # one of the defined LIBRARY_SOURCE_ROOT_DIRS. Adjust the list or the header path.
        message(FATAL_ERROR "Could not determine module for public header: '${HEADER_PATH}'. Please verify KERNELXDK_PUBLIC_HEADERS or LIBRARY_SOURCE_ROOT_DIRS.")
    endif()

    # Construct the destination subdirectory: e.g., kernelxdk/rip
    set(DEST_SUBDIR "kernelxdk/${MODULE_NAME}")

    # --- Debugging (remove these once confirmed fixed) ---
    message(STATUS "--- Debugging Public Headers ---")
    message(STATUS "HEADER_PATH: \"${HEADER_PATH}\"")
    message(STATUS "MODULE_NAME: \"${MODULE_NAME}\"")
    message(STATUS "DEST_SUBDIR: \"${DEST_SUBDIR}\"")
    message(STATUS "Full path for install: \"${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_PATH}\"")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_PATH}")
        message(FATAL_ERROR "ERROR: Header file does not exist: '${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_PATH}'")
    endif()
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_PATH}")
        message(FATAL_ERROR "ERROR: HEADER_PATH '${HEADER_PATH}' evaluates to a directory, not a file! Full path: '${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_PATH}'")
    endif()
    # --- END Debugging ---

    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_PATH}"
            DESTINATION include/${DEST_SUBDIR}
    )
endforeach()

# --- Installation for the Library Itself (static .lib/.a file) ---
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets # For find_package()
    ARCHIVE DESTINATION lib       # Where to install the .lib/.a file
)

# --- Define the INTERFACE_INCLUDE_DIRECTORIES for Consumers ---
# This tells CMake how targets linking to kernelXDK should find its headers.
# We are telling them that after installation, they need to look in 'INSTALL_PREFIX/include'.
# Then, since we installed headers to `include/kernelXDK/...`, they can include `<kernelXDK/module/header.h>`.
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include> # This is a conceptual path that CMake resolves
)


# --- Generate CMake Package Configuration Files ---
# This allows users to find your library using find_package(kernelXDK CONFIG REQUIRED)
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}"
)

# --- Add Subdirectories for Tests and Samples ---
add_subdirectory(test)
add_subdirectory(samples)