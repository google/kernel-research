#pragma once

#include <fcntl.h>
#include <keyutils.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include "util/error.cpp"

typedef int fd;

typedef fd pipefds[2];

class Syscalls {
    static void __check(int result, int expected = 0, const char* syscall_name = __builtin_FUNCTION()) {
        if (result == -1) // always fail in case of -1, errno will contain the error
            throw errno_error(syscall_name);
        else if (result != expected)
            throw ExpKitError("%s: returned with %d instead of the expected %d", syscall_name, result, expected);
    }

    template <typename T>
    static T __check_valid(T result, const char* syscall_name = __builtin_FUNCTION()) {
        if ((int64_t)result == -1) // always fail in case of -1, errno will contain the error
            throw errno_error(syscall_name);
        else if ((int64_t)result < 0)
            throw ExpKitError("%s: returned a negative number (%d) unexpectedly", syscall_name, result, result);
        return result;
    }

public:
    static int open(const char *file, int oflag) {
        return __check_valid(::open(file, oflag));
    }

    static void read(fd fd, void* buf, size_t n) {
        __check(::read(fd, buf, n), n);
    }

    static void write(fd fd, const void* buf, size_t n) {
        __check(::write(fd, buf, n), n);
    }

    static int ioctl(int fd, unsigned long int request, void* arg) {
        return __check_valid(::ioctl(fd, request, arg));
    }

    static void close(fd fd) {
        __check(::close(fd));
    }

    static void pipe(pipefds pipefds)  {
        __check(::pipe(pipefds));
    }
};
