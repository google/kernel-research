#pragma once

#include <fcntl.h>
#include <keyutils.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @brief A type definition for a file descriptor.
 */
typedef int fd;

/**
 * @ingroup util_classes
 * @brief A type definition for an array of two file descriptors for a pipe.
 */
typedef fd pipefds[2];

/**
 * @ingroup util_classes
 * @class Syscalls
 * @brief A wrapper class for common system calls with error checking.
 */
class Syscalls {
    /**
     * @brief Checks the result of a system call against an expected value.
     * @param result The actual result of the system call.
     * @param expected The expected result of the system call (defaults to 0).
     * @param syscall_name The name of the system call (defaults to the current function name).
     * @throws errno_error if the result is -1 (indicating a system error).
     * @throws ExpKitError if the result does not match the expected value.
     */
    static void __check(int result, int expected = 0,
                        const char* syscall_name = __builtin_FUNCTION());

    /**
     * @brief Checks if the result of a system call is valid (not -1 and not negative).
     * @tparam T The type of the result.
     * @param result The result of the system call.
     * @param syscall_name The name of the system call (defaults to the current function name).
     * @return The result of the system call if it is valid.
     * @throws errno_error if the result is -1 (indicating a system error).
     * @throws ExpKitError if the result is a negative number unexpectedly.
     */
    template <typename T>
    static T __check_valid(T result,
                            const char* syscall_name = __builtin_FUNCTION());

public:
    /**
     * @brief Wraps the open system call with error checking.
     * @param file The path to the file.
     * @param oflag The flags for opening the file.
     * @return The file descriptor.
     * @throws ExpKitError if the system call fails.
     */
    static int open(const char* file, int oflag);

    /**
     * @brief Wraps the read system call with error checking.
     * @param fd The file descriptor to read from.
     * @param buf The buffer to store the read data.
     * @param n The number of bytes to read.
     * @throws ExpKitError if the system call fails or reads an unexpected number
     * of bytes.
     */
    static void read(fd fd, void* buf, size_t n);

    /**
     * @brief Wraps the write system call with error checking.
     * @param fd The file descriptor to write to.
     * @param buf The buffer containing the data to write.
     * @param n The number of bytes to write.
     * @throws ExpKitError if the system call fails or writes an unexpected number
     * of bytes.
     */
    static void write(fd fd, const void* buf, size_t n);

    /**
     * @brief Wraps the ioctl system call with error checking.
     * @param fd The file descriptor.
     * @param request The ioctl request.
     * @param arg The argument for the ioctl request.
     * @return The result of the ioctl system call.
     * @throws ExpKitError if the system call fails.
     */
    static int ioctl(int fd, unsigned long int request, void* arg);

    /**
     * @brief Wraps the close system call with error checking.
     * @param fd The file descriptor to close.
     * @throws ExpKitError if the system call fails.
     */
    static void close(fd fd);

    /**
     * @brief Wraps the pipe system call with error checking.
     * @param pipefds An array to hold the file descriptors for the read and write
     * ends of the pipe.
     * @throws ExpKitError if the system call fails.
     */
    static void pipe(pipefds pipefds);
};