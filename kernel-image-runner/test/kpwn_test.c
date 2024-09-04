/*
 * Copyright 2024 Google LLC
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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "../../third_party/kernel-modules/kpwn/kpwn.h"
#include <sys/reboot.h>    /* Definition of RB_* constants */
#include <unistd.h>

long check(long res, const char* cmd) {
    if (res < 0) {
        printf("%s failed with %ld (errno=%d)\n", cmd, res, errno);
        usleep(40 * 1000);
        _exit(1);
    }
    return res;
}

#define CHECK(VAR) check(VAR, #VAR)

void rip_control_test(int fd) {
    printf("kpwn_test: calling KASLR_LEAK...\n");
    uint64_t kaslr_base = 0x1337;
    CHECK(ioctl(fd, KASLR_LEAK, &kaslr_base));
    printf("kaslr base: %lx\n", kaslr_base);

    printf("kpwn_test: calling WIN_TARGET...\n");
    uint64_t win_target = 0x1337;
    CHECK(ioctl(fd, WIN_TARGET, &win_target));
    printf("win_target: %lx\n", win_target);

    printf("kpwn_test: calling ALLOC_BUFFER...\n");
    kpwn_message msg = { 1024 };
    CHECK(ioctl(fd, ALLOC_BUFFER, &msg));
    printf("kernel buffer address = 0x%lx\n", msg.kernel_addr);

    printf("kpwn_test: calling ARB_WRITE ioctl...\n");
    msg.data = malloc(msg.length);
    uint64_t* rop = (uint64_t*)&msg.data[0];
    rop[0] = 0xffffff4141414141;
    rop[1] = win_target;
    rop[2] = 0xffffff4343434343;
    rop[3] = 0xffffff4444444444;
    CHECK(ioctl(fd, ARB_WRITE, &msg));

    printf("kpwn_test: calling ARB_READ ioctl...\n");
    msg.kernel_addr += 8;
    msg.length -= 8;
    free(msg.data);
    msg.data = malloc(msg.length);
    memset(msg.data, 0, msg.length);
    CHECK(ioctl(fd, ARB_READ, &msg));
    printf("result = %lx\n", *(uint64_t*)&msg.data[0]);
    if (*(uint64_t*)&msg.data[0] != win_target) {
        printf("[-] excepted data[0] to be 0x%lx, but it was 0x%lx", win_target, *(uint64_t*)&msg.data[0]);
        _exit(2);
    }

    printf("kpwn_test: calling RIP_CONTROL ioctl...\n");
    rip_control_args rip = { .rsp = (uint64_t) msg.kernel_ptr, .regs_to_set = RSP, .action = RET };
    usleep(40 * 1000);
    CHECK(ioctl(fd, RIP_CONTROL, &rip));
}

void kprobe_test(int fd) {
    kprobe_args args = { .function_name = "__kmalloc", .pid_filter = getpid(), .log_mode = ENTRY_WITH_CALLSTACK | RETURN };
    CHECK(ioctl(fd, INSTALL_KPROBE, &args));

    kpwn_message msg = { 1024 };
    CHECK(ioctl(fd, ALLOC_BUFFER, &msg));
    printf("kernel buffer address = 0x%lx\n", msg.kernel_addr);
}

int main(int argc, const char** argv) {
    printf("kpwn_test: opening device...\n");
    int fd = CHECK(open("/dev/kpwn", O_RDWR));

    bool mode_kprobe_test = 0;
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], "--kprobe-test"))
            mode_kprobe_test = 1;

    if (mode_kprobe_test)
        kprobe_test(fd);
    else
        rip_control_test(fd);

    printf("kpwn_test: closing device...\n");
    usleep(40 * 1000);
    CHECK(close(fd));

    printf("kpwn_test: exiting...\n");
    return 0;
}