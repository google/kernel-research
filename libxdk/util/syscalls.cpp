// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fcntl.h>
#include <keyutils.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <xdk/util/error.h>
#include <xdk/util/syscalls.h>

void Syscalls::__check(int result, int expected, const char* syscall_name) {
  if (result == -1)  // always fail in case of -1, errno will contain the error
    throw errno_error(syscall_name);
  else if (result != expected)
    throw ExpKitError("%s: returned with %d instead of the expected %d",
                      syscall_name, result, expected);
}

template <typename T>
T Syscalls::__check_valid(T result, const char* syscall_name) {
  if ((int64_t)result ==
      -1)  // always fail in case of -1, errno will contain the error
    throw errno_error(syscall_name);
  else if ((int64_t)result < 0)
    throw ExpKitError("%s: returned a negative number (%d) unexpectedly",
                      syscall_name, result, result);
  return result;
}

int Syscalls::open(const char* file, int oflag) {
  return __check_valid(::open(file, oflag));
}

void Syscalls::read(fd fd, void* buf, size_t n) {
  __check(::read(fd, buf, n), n);
}

void Syscalls::write(fd fd, const void* buf, size_t n) {
  __check(::write(fd, buf, n), n);
}

int Syscalls::ioctl(int fd, unsigned long int request, void* arg) {
  return __check_valid(::ioctl(fd, request, arg));
}

void Syscalls::close(fd fd) { __check(::close(fd)); }

void Syscalls::pipe(pipefds pipefds) { __check(::pipe(pipefds)); }
