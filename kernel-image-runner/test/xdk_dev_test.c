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
#include "../../third_party/kernel-modules/xdk_device/xdk_device.h"
#include <sys/reboot.h>    /* Definition of RB_* constants */

long check(long res, const char* cmd) {
    if (res < 0) {
        printf("%s failed with %ld (errno=%d)\n", cmd, res, errno);
        usleep(40 * 1000);
        _exit(1);
    }
    return res;
}

#define CHECK(VAR) check(VAR, #VAR)

void wait() {
    usleep(40 * 1000);
}

int xdk_fd;

void rip_control_test() {
    printf("xdk_dev_test: calling KASLR_LEAK...\n");
    uint64_t kaslr_base = 0x1337;
    CHECK(ioctl(xdk_fd, KASLR_LEAK, &kaslr_base));
    printf("kaslr base: %lx\n", kaslr_base);

    printf("xdk_dev_test: calling WIN_TARGET...\n");
    uint64_t win_target = 0x1337;
    CHECK(ioctl(xdk_fd, WIN_TARGET, &win_target));
    printf("win_target: %lx\n", win_target);

    printf("xdk_dev_test: calling ALLOC_BUFFER...\n");
    xdk_message msg = { 1024 };
    CHECK(ioctl(xdk_fd, ALLOC_BUFFER, &msg));
    printf("kernel buffer address = 0x%lx\n", msg.kernel_addr);

    printf("xdk_dev_test: calling ARB_WRITE ioctl...\n");
    msg.data = malloc(msg.length);
    uint64_t* rop = (uint64_t*)&msg.data[0];
    rop[0] = 0xffffff4141414141;
    rop[1] = win_target;
    rop[2] = 0xffffff4343434343;
    rop[3] = 0xffffff4444444444;
    CHECK(ioctl(xdk_fd, ARB_WRITE, &msg));

    printf("xdk_dev_test: calling ARB_READ ioctl...\n");
    msg.kernel_addr += 8;
    msg.length -= 8;
    free(msg.data);
    msg.data = malloc(msg.length);
    memset(msg.data, 0, msg.length);
    CHECK(ioctl(xdk_fd, ARB_READ, &msg));
    printf("result = %lx\n", *(uint64_t*)&msg.data[0]);
    if (*(uint64_t*)&msg.data[0] != win_target) {
        printf("[-] excepted data[0] to be 0x%lx, but it was 0x%lx", win_target, *(uint64_t*)&msg.data[0]);
        _exit(2);
    }

    printf("xdk_dev_test: calling RIP_CONTROL ioctl...\n");
    rip_control_args rip = { .rsp = (uint64_t) msg.kernel_ptr, .regs_to_set = RSP, .action = RET };
    wait();
    CHECK(ioctl(xdk_fd, RIP_CONTROL, &rip));
}

void kprobe_test() {
    kprobe_args args = { .function_name = "__kmalloc", .pid_filter = getpid(), .log_mode = ENTRY_WITH_CALLSTACK | RETURN };
    CHECK(ioctl(xdk_fd, INSTALL_KPROBE, &args));

    xdk_message msg = { 1024 };
    CHECK(ioctl(xdk_fd, ALLOC_BUFFER, &msg));
    printf("kernel buffer address = 0x%lx\n", msg.kernel_addr);
}

// 16 bytes are converted into: "00 11 22 33 44 55 66 77   88 99 AA BB CC DD EE FF  |  0123456789ABCDEF\n" (70 bytes)
static void hexdump(char* dst, const uint8_t* buf, int len) {
    char text[17] = { };
    for (int i = 0; i < len; i++) {
        dst += sprintf(dst, "%02X ", buf[i]);
        int o = i % 16;
        text[o] = ' ' <= buf[i] && buf[i] <= '~' ? buf[i] : '.';
        if (i == len - 1)
            dst += sprintf(dst, "%*s |  %.*s\n", 3 * (15 - o) + (o < 8 ? 1 : 0), "", o + 1, text);
        else if (o == 7)
                    dst += sprintf(dst, " ");
        else if (o == 15)
            dst += sprintf(dst, " |  %s\n", text);
    }
}

static void hexdump2(const void* buf, int len) {
    char* dst = (char*) malloc(((len - 1) / 16 + 1) * 70);
    hexdump(dst, (uint8_t*)buf, len);
    puts(dst);
    free(dst);
}

typedef struct pipe_buf_operations {
    uint64_t confirm; /*     0     8 */
    uint64_t release; /*     8     8 */
    uint64_t try_steal; /*    16     8 */
    uint64_t get; /*    24     8 */
    /* size: 32, cachelines: 1, members: 4 */
} pipe_buf_operations;

typedef struct pipe_buffer {
    uint64_t page;       /*     0     8 */
    uint32_t offset;     /*     8     4 */
    uint32_t len;        /*    12     4 */
    uint64_t ops;        /*    16     8 */
    uint32_t flags;      /*    24     4 */
    uint64_t private_;   /*    32     8 */
    /* size: 40, cachelines: 1, members: 6 */
} pipe_buffer;

uint64_t get_sym_addr(const char* name) {
    sym_addr sym_addr;
    strncpy(sym_addr.symbol_name, name, sizeof(sym_addr.symbol_name));
    CHECK(ioctl(xdk_fd, SYM_ADDR, &sym_addr));
    return sym_addr.symbol_addr;
}

uint64_t alloc_buffer(void* data, uint64_t len) {
    xdk_message msg = { .data = (uint8_t*)data, .length = len };
    CHECK(ioctl(xdk_fd, ALLOC_BUFFER, &msg));
    return msg.kernel_addr;
}

void arb_read(uint64_t kernel_addr, void* buf, uint64_t len) {
    xdk_message msg = { .length = len, .kernel_addr = kernel_addr, .data = (uint8_t*)buf };
    memset(msg.data, 'A', msg.length);
    CHECK(ioctl(xdk_fd, ARB_READ, &msg));
}

void arb_write(uint64_t kernel_addr, void* buf, uint64_t len) {
    xdk_message msg = { .length = len, .kernel_addr = kernel_addr, .data = (uint8_t*)buf };
    CHECK(ioctl(xdk_fd, ARB_WRITE, &msg));
}

kprobe_log* install_kprobe(const char* function_name, uint8_t arg_count, const char* call_stack_filter) {
    kprobe_log* log = (kprobe_log*) malloc(64 * 1024);
    log->struct_size = 64 * 1024;
    log->missed_logs = 0;
    log->next_offset = 0;
    log->entry_count = 0;

    //printf("log addr = %p, call_stack_ptr = %p\n", log, log->entries[0].call_stack);

    kprobe_args args = {
        .arg_count = arg_count,
        .pid_filter = getpid(),
        .log_mode = ENTRY_WITH_CALLSTACK | RETURN | CALL_LOG,
        .logs = log
    };
    strncpy(args.function_name, function_name, sizeof(args.function_name));
    if (call_stack_filter)
        strncpy(args.log_call_stack_filter, call_stack_filter, sizeof(args.log_call_stack_filter));
    CHECK(ioctl(xdk_fd, INSTALL_KPROBE, &args));
    return log;
}

void pipebuf_test() {
    printf("xdk_dev_test: calling SYM_ADDR...\n");
    uint64_t rip_target = get_sym_addr("dump_stack");

    kprobe_log* log = install_kprobe("__kmalloc", 1, "create_pipe_files");

    printf("calling pipe...\n");
    int fds[2];
    CHECK(pipe(fds));
    write(fds[1], "pwn", 3);
    wait();

    printf("log count: %lu\n", log->entry_count);
    kprobe_log_entry* entry = log->entries;
    for (int i = 0; i < log->entry_count; i++) {
        printf("#1: kmalloc(%d) = %p\n  call stack: %s\n", (int)entry->arguments[0], (void*)entry->return_value, entry->call_stack);
        //hexdump2(entry_ptr->call_stack, entry_ptr->call_stack_size);
        entry = (kprobe_log_entry*)(((uint8_t*) entry) + entry->entry_size);
    }

    if (log->entry_count == 0) {
        printf("error: pipe_buffer allocation could not be recorded...\n");
        return;
    }
    wait();


    uint64_t pb_addr = log->entries[0].return_value;
    pipe_buffer pb;
    arb_read(pb_addr, &pb, sizeof(pb));
    hexdump2(&pb, sizeof(pb));
    printf("ops ptr = 0x%lx\n", pb.ops);
    printf("pipe_buffer addr = 0x%lx\n", pb_addr);
    wait();

    pipe_buf_operations fake_ops = { .release = 0x4141414141414141 };
    pb.ops = alloc_buffer(&fake_ops, sizeof(fake_ops));
    printf("fake pipe_buf_ops addr = 0x%lx\n", pb.ops);
    arb_write(pb_addr, &pb, sizeof(pb));

    wait();
    close(fds[0]);
    close(fds[1]);
}

int main(int argc, const char** argv) {
    void (*test_func)() = rip_control_test;

    printf("xdk_dev_test: opening device...\n");
    xdk_fd = CHECK(open("/dev/" DEVICE_NAME, O_RDWR));
    wait();

    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], "--kprobe-test"))
            test_func = kprobe_test;
        else if (!strcmp(argv[i], "--pipebuf-test"))
            test_func = pipebuf_test;

    test_func();

    wait();
    printf("xdk_dev_test: closing device...\n");
    wait();
    CHECK(close(xdk_fd));

    printf("xdk_dev_test: exiting...\n");
    return 0;
}
