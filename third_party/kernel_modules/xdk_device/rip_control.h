/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
*/

#pragma once

#include "utils.h"
#include "xdk_device.h"

volatile uint64_t saved_r12;
volatile uint64_t saved_r13;
volatile uint64_t saved_r14;
volatile uint64_t saved_r15;
volatile uint64_t saved_rbx;
volatile uint64_t saved_rsp;
volatile uint64_t saved_rbp;

#define NOINST __attribute__((no_instrument_function))

void noinline rip_control(rip_control_args* regs) {
    register rip_control_args* regs_asm asm("r15") = regs;

    const char* action_name = 1 <= regs->action && regs->action <= sizeof(rip_action_names) / sizeof(rip_action_names[0]) ? rip_action_names[regs->action] : "INVALID";

    LOG("rip_control: action=%s (0x%llx), rsp=0x%llx, value@rsp=0x%llx, regs_to_set=0x%llx, rip=0x%llx, saved_rsp=0x%llx, value@saved_rsp=0x%llx",
        action_name, regs->action, regs->rsp, regs->rsp == 0 ? 0 : *(uint64_t*)regs->rsp, regs->regs_to_set, regs->rip, saved_rsp, *(uint64_t*)saved_rsp);

    if (regs->action != JMP_RIP && regs->action != CALL_RIP && regs->action != RET && regs->action != NONE) {
        LOG("rip_control: invalid action (0x%llx)!", regs->action);
        return;
    }

    if ((regs->action == RET) && (!regs->rsp || !(regs->regs_to_set & RSP)))
        LOG("rip_control: executing RET without setting RSP to non-zero value. Are you sure?");

    if ((regs->action == JMP_RIP || regs->action == CALL_RIP) && !regs->rip)
        LOG("rip_control: executing JMP_RIP or CALL_RIP with zero RIP ptr. Are you sure?");

    asm volatile (
        ".intel_syntax noprefix\n\t"  // switch to Intel syntax

        // r15 + 0x88 == rip_control_args.regs_to_set
        "set_rax:"
        "  test QWORD PTR [r15 + 0x88], 0x000001\n\t" // regs_to_set.RAX == 0x000001
        "  je set_rbx\n\t"
        "  mov rax, [r15 + 0x00]\n\t"
        "set_rbx:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000002\n\t" // regs_to_set.RBX == 0x000002
        "  je set_rcx\n\t"
        "  mov rbx, [r15 + 0x08]\n\t"
        "set_rcx:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000004\n\t" // regs_to_set.RCX == 0x000004
        "  je set_rdx\n\t"
        "  mov rcx, [r15 + 0x10]\n\t"
        "set_rdx:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000008\n\t" // regs_to_set.RDX == 0x000008
        "  je set_rsi\n\t"
        "  mov rdx, [r15 + 0x18]\n\t"
        "set_rsi:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000010\n\t" // regs_to_set.RSI == 0x000010
        "  je set_rdi\n\t"
        "  mov rsi, [r15 + 0x20]\n\t"
        "set_rdi:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000020\n\t" // regs_to_set.RDI == 0x000020
        "  je set_rbp\n\t"
        "  mov rdi, [r15 + 0x28]\n\t"
        "set_rbp:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000040\n\t" // regs_to_set.RBP == 0x000040
        "  je set_rsp\n\t"
        "  mov rbp, [r15 + 0x30]\n\t"
        "set_rsp:"
        "  test QWORD PTR [r15 + 0x88], 0x000080\n\t" // regs_to_set.RSP == 0x000080
        "  je set_r8\n\t"
        "  mov rsp, [r15 + 0x38]\n\t"
        "set_r8:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000100\n\t" // regs_to_set.R8 == 0x000100
        "  je set_r9\n\t"
        "  mov r8,  [r15 + 0x40]\n\t"
        "set_r9:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000200\n\t" // regs_to_set.R9 == 0x000200
        "  je set_r10\n\t"
        "  mov r9,  [r15 + 0x48]\n\t"
        "set_r10:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000400\n\t" // regs_to_set.R10 == 0x000400
        "  je set_r11\n\t"
        "  mov r10, [r15 + 0x50]\n\t"
        "set_r11:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x000800\n\t" // regs_to_set.R11 == 0x000800
        "  je set_r12\n\t"
        "  mov r11, [r15 + 0x58]\n\t"
        "set_r12:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x001000\n\t" // regs_to_set.R12 == 0x001000
        "  je set_r13\n\t"
        "  mov r12, [r15 + 0x60]\n\t"
        "set_r13:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x002000\n\t" // regs_to_set.R13 == 0x002000
        "  je set_r14\n\t"
        "  mov r13, [r15 + 0x68]\n\t"
        "set_r14:\n\t"
        "  test QWORD PTR [r15 + 0x88], 0x004000\n\t" // regs_to_set.R14 == 0x004000
        "  je action_jmp_rip\n\t"
        "  mov r14, [r15 + 0x70]\n\t"

        // r15+0x90 == rip_control_args.action
        "action_jmp_rip:\n\t"
        "  cmp QWORD PTR [r15 + 0x90], 0x01\n\t" // rip_action.JMP_RIP == 0x01
        "  jne action_call_rip\n\t"
        "  mov r15, QWORD PTR[r15 + 0x80]\n\t"   // r15 = rip_control_args.rip
        ANNOTATE_RETPOLINE_SAFE
        "  jmp r15\n\t"
        "  int3\n\t"

        "action_call_rip:\n\t"
        "  cmp QWORD PTR [r15 + 0x90], 0x02\n\t" // rip_action.CALL_RIP == 0x02
        "  jne action_ret\n\t"
        "  mov r15, QWORD PTR[r15 + 0x80]\n\t"   // r15 = rip_control_args.rip
        ANNOTATE_RETPOLINE_SAFE
        "  call r15\n\t"
        "  jmp end\n\t"

        "action_ret:\n\t"
        "  cmp QWORD PTR [r15 + 0x90], 0x03\n\t" // rip_action.RET == 0x03
        "  jne action_none\n\t"
        "  mov r15, [r15 + 0x78]\n\t"            // r15 = rip_control_args.r15
        ANNOTATE_RETPOLINE_SAFE
        "  ret\n\t"
        "  int3\n\t"

        "action_none:\n\t"
        "  cmp QWORD PTR [r15 + 0x90], 0x04\n\t" // rip_action.NONE == 0x04
        "  jne action_invalid\n\t"
        "  jmp end\n\t"

        "action_invalid:\n\t"
        "  int3\n\t"

        "end:"

        ".att_syntax prefix\n\t" // switch back to AT&T syntax
        : // No output operands
        : "r"(regs_asm)
        : // No clobbered registers
    );

    LOG("rip_control, after asm");
}

void noinline NOINST rip_control_wrapper(rip_control_args* regs) {
    __asm__ (
        ".intel_syntax noprefix\n"
        "mov saved_r12, r12\n"
        "mov saved_r13, r13\n"
        "mov saved_r14, r14\n"
        "mov saved_r15, r15\n"
        "mov saved_rbx, rbx\n"
        "mov saved_rsp, rsp\n"
        "mov saved_rbp, rbp\n"
        ".att_syntax prefix\n"
    );
    rip_control(regs);
}

void noinline NOINST rip_control_recover(void) {
    __asm__ (
        ".intel_syntax noprefix\n"
        "mov r12, saved_r12\n"
        "mov r13, saved_r13\n"
        "mov r14, saved_r14\n"
        "mov r15, saved_r15\n"
        "mov rbx, saved_rbx\n"
        "mov rsp, saved_rsp\n"
        "mov rbp, saved_rbp\n"
        ".att_syntax prefix\n"
    );
}
