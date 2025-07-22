/*
 * Copyright 2025 Google LLC
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

#pragma once

#include <stdint.h>
#include <sys/types.h>

#define DEVICE_NAME "kpwn"

typedef struct kpwn_message {
    uint64_t length;
    uint8_t* data;
    union {
        uint64_t kernel_addr;
        void* kernel_ptr;
    };
    uint8_t gfp_account;
} kpwn_message;

enum kpwn_cmd { ALLOC_BUFFER = 0x1000, KFREE, KASLR_LEAK, WIN_TARGET, RIP_CONTROL, ARB_READ, ARB_WRITE, INSTALL_KPROBE, PRINTK, SYM_ADDR, REMOVE_KPROBE, GET_RIP_CONTROL_RECOVERY, CHECK_WIN };

const char* kpwn_cmd_names[] = { "ALLOC_BUFFER", "KFREE", "KASLR_LEAK", "WIN_TARGET",
    "RIP_CONTROL", "ARB_READ", "ARB_WRITE", "INSTALL_KPROBE", "PRINTK", "SYM_ADDR",
    "REMOVE_KPROBE", "GET_RIP_CONTROL_RECOVERY", "CHECK_WIN" };

enum kpwn_error {
    SUCCESS = 0,
    ERROR_GENERIC = 0x1000,
    ERROR_UNKNOWN_COMMAND = 0x1001,
    ERROR_ALLOC = 0x1002,
    ERROR_COPY_FROM_USER_STRUCT = 0x1003,
    ERROR_COPY_FROM_USER_DATA = 0x1004,
    ERROR_COPY_TO_USER_STRUCT = 0x1005,
    ERROR_COPY_TO_USER_DATA = 0x1006,
    ERROR_UNKNOWN_SYMBOL = 0x1007,
};

const char* kpwn_errors_names[] = {
    "ERROR_GENERIC",
    "ERROR_UNKNOWN_COMMAND",
    "ERROR_ALLOC",
    "ERROR_COPY_FROM_USER_STRUCT",
    "ERROR_COPY_FROM_USER_DATA",
    "ERROR_COPY_TO_USER_STRUCT",
    "ERROR_COPY_TO_USER_DATA",
    "ERROR_UNKNOWN_SYMBOL",
 };

enum regs_to_set: unsigned long {
    RAX = 0x000001,
    RBX = 0x000002,
    RCX = 0x000004,
    RDX = 0x000008,
    RSI = 0x000010,
    RDI = 0x000020,
    RBP = 0x000040,
    RSP = 0x000080,
    R8  = 0x000100,
    R9  = 0x000200,
    R10 = 0x000400,
    R11 = 0x000800,
    R12 = 0x001000,
    R13 = 0x002000,
    R14 = 0x004000,
    //R15 = 0x008000,
    ALL = 0xffffffff,
};

enum rip_action {
    JMP_RIP = 0x1, // jmp r15 (r15 == rip_control_args.rip)
    CALL_RIP = 0x2, // call r15 (r15 == rip_control_args.rip)
    RET = 0x3,
    NONE = 0x4,
};

typedef struct {
    // 0x00
    uint64_t rax, rbx, rcx, rdx;
    // 0x20
    uint64_t rsi, rdi, rbp, rsp;
    // 0x40
    uint64_t r8,  r9,  r10, r11;
    // 0x60
    uint64_t r12, r13, r14, r15;
    // 0x80
    uint64_t rip;
    // 0x88
    uint64_t regs_to_set;
    // 0x90
    uint64_t action;
} rip_control_args;

enum kprobe_log_mode {
    SILENT = 0x0,
    ENTRY = 0x1,
    ENTRY_CALLSTACK = 0x2,
    RETURN = 0x4,
    RETURN_CALLSTACK = 0x8,
    CALL_LOG = 0x10,
    ENTRY_WITH_CALLSTACK = ENTRY | ENTRY_CALLSTACK,
    RETURN_WITH_CALLSTACK = RETURN | RETURN_CALLSTACK
};

typedef struct {
    volatile uint64_t entry_size;
    volatile uint64_t arguments[6];
    volatile uint64_t return_value;
    volatile uint64_t call_stack_size;
    volatile uint8_t call_stack[];
} kprobe_log_entry;

typedef struct {
    volatile uint64_t struct_size;
    volatile uint64_t entry_count;
    volatile uint64_t next_offset; // next writable offset
    volatile uint64_t missed_logs; // number of logs could not be written to due insufficient buffer space
    kprobe_log_entry entries[];
} kprobe_log;

typedef struct {
    char function_name[128];
    pid_t pid_filter;
    uint8_t arg_count;
    uint8_t log_mode; // kprobe_log_mode
    char log_call_stack_filter[128];
    kprobe_log* logs;
    void* installed_kprobe;
} kprobe_args;

typedef struct {
    char symbol_name[128];
    uint64_t symbol_addr;
} sym_addr;

