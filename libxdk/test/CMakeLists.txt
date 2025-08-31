# test/CMakeLists.txt
project(kernelXDKTests) # Renamed project name

set(TEST_SRCS
    TestRunner.cpp
    TestUtils.cpp
    TestEnvironment.cpp
    TestSuite.cpp
    main.cpp
    logging/PrintfLogger.cpp
    logging/TapLogger.cpp
)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
set(KXDB_DOWNLOAD_URL "https://storage.googleapis.com/kernelxdk/db/kernelctf.kxdb")
set(KXDB_OUTPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/artifacts/kernelctf.kxdb")

add_executable(${PROJECT_NAME} ${TEST_SRCS}) # ${PROJECT_NAME} here is kernelXDKTests

# Link the test executable to your main library
target_link_libraries(${PROJECT_NAME} PRIVATE kernelXDK) # Renamed library

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/logging
    # Ensure these paths are correct relative to 'test/'
    ${CMAKE_CURRENT_SOURCE_DIR}/../xdk_device
    ${CMAKE_CURRENT_SOURCE_DIR}/../rip
    ${CMAKE_CURRENT_SOURCE_DIR}/../target
    ${CMAKE_CURRENT_SOURCE_DIR}/../util
    ${CMAKE_CURRENT_SOURCE_DIR}/../pivot
    ${CMAKE_CURRENT_SOURCE_DIR}/../payloads
)

if(NOT EXISTS "${KXDB_OUTPUT_FILE}")
    message(STATUS "Downloading ${KXDB_DOWNLOAD_URL} to ${KXDB_OUTPUT_FILE}...")
    file(DOWNLOAD "${KXDB_DOWNLOAD_URL}" "${KXDB_OUTPUT_FILE}" TLS_VERIFY TRUE)
endif()

add_custom_command(
    TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/artifacts"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/artifacts"
    COMMENT "Copying test artifacts for ${PROJECT_NAME}"
)

enable_testing()
add_test(NAME kernelXDKMainTests COMMAND ${PROJECT_NAME} --test-suites StaticTests --tests "^TODO") # Renamed test name
