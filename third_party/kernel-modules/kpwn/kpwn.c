// SPDX-License-Identifier: GPL-2.0
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/version.h>
#include <asm/setup.h>
#include "kpwn.h"
#include "utils.h"
#include "rip_control.h"
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

#define DEVICE_NAME "kpwn"

unsigned long (*_kallsyms_lookup_name)(const char *name) = 0;
int (*_sprint_backtrace)(char *buffer, unsigned long address) = 0;
int (*_stack_trace_save_tsk_reliable)(struct task_struct *tsk, unsigned long *store, unsigned int size) = 0;
int (*_stack_trace_save_tsk)(struct task_struct *tsk, unsigned long *store, unsigned int size, unsigned int skipnr) = 0;

#ifndef __GFP_ACCOUNT
#define __GFP_ACCOUNT 0
#endif

static long alloc_buffer(kpwn_message* msg, void* user_ptr) {
    msg->kernel_ptr = 0;
    STRUCT_FROM_USER(msg, user_ptr);
    msg->kernel_ptr = CHECK_ALLOC(kmalloc(msg->length, GFP_KERNEL | (msg->gfp_account ? __GFP_ACCOUNT : 0)));
    if (msg->data)
        DATA_FROM_USER(msg->kernel_ptr, msg->data, msg->length);
    STRUCT_TO_USER(msg, user_ptr);
    return SUCCESS;
}

unsigned long won = 0;

static NOINST void win_target(void) {
    //LOG("win_target was called.\n\n!!! YOU WON !!! \n");
    won = 1;
}

unsigned long kaslr_base = 0;

typedef struct kprobe_data {
    kprobe_log_entry* log_entry_user_ptr;
} kprobe_data;

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

LIST_HEAD(kprobes);

typedef struct {
    struct list_head list;
    struct kretprobe kretprobe;
    kprobe_args args;
} kretprobe_wrapper;

#define CALL_STACK_SIZE 4096
DEFINE_PER_CPU(char[CALL_STACK_SIZE], cpu_call_stack);

#define GET_CPU_VAR(var_name) ({ typeof(var_name) __temp = get_cpu_var(var_name); put_cpu_var(var_name); __temp; })
#define SET_CPU_VAR(var_name, new_value) ({ get_cpu_var(var_name) = new_value; put_cpu_var(var_name); })

static int my_dump_stack(const char* hooked_func, char* buf, int buf_size) {
    unsigned long stack_trace[32];
    char function_name[KSYM_NAME_LEN];
    int buf_idx = 0;

    // skip first 5 entries, they are:
    //   my_dump_stack.isra.0+0x3b/0xb0 [kpwn]
    //   entry_handler+0x98/0xb0 [kpwn]
    //   pre_handler_kretprobe+0x37/0x90
    //   kprobe_ftrace_handler+0x1a2/0x240
    //   0xffffffffc03db0dc   // optimized area(?)
    if (!_stack_trace_save_tsk) {
        LOG("my_dump_stack: stack_trace_save_tsk is not available");
        return 0;
    }

    int len = _stack_trace_save_tsk(current, stack_trace, ARRAY_SIZE(stack_trace), 5);
    if (len < 0) {
        LOG("my_dump_stack: FAILED with len=%d < 0", len);
        dump_stack();
        return 0;
    }

    int i;
    for (i = 0; i < len; i++) {
        _sprint_backtrace(function_name, stack_trace[i]);
        buf_idx += snprintf(&buf[buf_idx], buf_size - buf_idx, "%s%s", (buf_idx == 0 ? "" : " <- "), function_name);
    }
    //LOG("KPROBE: %s: stack trace: %s", hooked_func, stack_trace_buf);
    return buf_idx;
}

struct kretprobe* get_kretprobe_(struct kretprobe_instance *ri) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    return get_kretprobe(ri);
#else
    return ri->rp;
#endif
}

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct kretprobe* rp = get_kretprobe_(ri);
    kretprobe_wrapper* wr = container_of(rp, kretprobe_wrapper, kretprobe);
    kprobe_data* data = (kprobe_data*) ri->data;

    // !current->mm - skipping kernel threads
    if (!current->mm || (wr->args.pid_filter != -1 && current->pid != wr->args.pid_filter))
        return 1;

    bool entry_log = wr->args.log_mode & ENTRY;
    bool print_callstack = wr->args.log_mode & ENTRY_CALLSTACK;
    bool log_call = wr->args.log_mode & CALL_LOG;
    bool log_filter = !!wr->args.log_call_stack_filter[0];
    if (!entry_log && !log_call)
        return 0;

    kprobe_log_entry new_entry = { 0, { regs->di, regs->si, regs->dx, regs->cx, regs->r8, regs->r9 }, 0, 0 };

    // TODO: also filter out if this comes from install_kprobe or remove_kprobe (or any function which is within kpwn module)
    char* call_stack_buf = get_cpu_ptr(cpu_call_stack);
    bool filter_out = false;
    if (log_call || print_callstack || log_filter) {
        new_entry.call_stack_size = my_dump_stack(rp->kp.symbol_name, call_stack_buf, CALL_STACK_SIZE);
        if (log_filter && new_entry.call_stack_size)
            filter_out = !strstr(call_stack_buf, wr->args.log_call_stack_filter);
    }

    if (filter_out) {
        put_cpu_ptr(cpu_call_stack);
        return 1;
    }

    if (entry_log) {
        char args_str[128];
        char* args_ptr = &args_str[0];
        int i;
        for (i = 0; i < wr->args.arg_count; i++)
            args_ptr += snprintf(args_ptr, ARRAY_SIZE(args_str) - (args_ptr - args_str), "%s0x%llx", i == 0 ? "" : ", ", new_entry.arguments[i]);
        LOG("KPROBE: %s(%s)", rp->kp.symbol_name, args_str);
    }

    if (log_call || print_callstack) {
        if (print_callstack)
            LOG("KPROBE:   stack trace: %s", call_stack_buf);

        if (log_call) {
            kprobe_log log;
            STRUCT_FROM_USER(&log, wr->args.logs);
            int free_space = log.struct_size - sizeof(kprobe_log) - log.next_offset;
            new_entry.entry_size = sizeof(new_entry) + new_entry.call_stack_size;

            if (free_space < new_entry.entry_size) {
                data->log_entry_user_ptr = 0;
                log.missed_logs++;
                LOG("KPROBE:   ERROR: could not log call, there were not enough space in user-space buffer (free_space=%d, log_entry_size=%llu)", free_space, new_entry.entry_size);
            } else {
                data->log_entry_user_ptr = (kprobe_log_entry*)(((uint8_t*)&wr->args.logs->entries) + log.next_offset);
                DATA_TO_USER(call_stack_buf, (uint8_t*)&data->log_entry_user_ptr->call_stack, new_entry.call_stack_size);
                STRUCT_TO_USER(&new_entry, data->log_entry_user_ptr);

                // TODO: this should be written atomicly... fix race
                // this should be rewritten to use user-space memory directly (GUP + kmap)
                // or just handle buffers in kernel-space and give API to read logs
                log.next_offset += new_entry.entry_size;
                log.entry_count++;
            }
            STRUCT_TO_USER(&log, wr->args.logs);
        }
    }

    put_cpu_ptr(cpu_call_stack);
    return 0;
}
NOKPROBE_SYMBOL(entry_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct kretprobe* rp = get_kretprobe_(ri);
    kretprobe_wrapper* wr = container_of(rp, kretprobe_wrapper, kretprobe);
    struct kprobe_data *data = (struct kprobe_data *)ri->data;

    if (wr->args.log_mode & RETURN) {
        LOG("KPROBE: %s: returned 0x%lx", rp->kp.symbol_name, regs_return_value(regs));
    }

    if (wr->args.log_mode & RETURN_CALLSTACK) {
        char* call_stack_buf = get_cpu_ptr(cpu_call_stack);
        my_dump_stack(rp->kp.symbol_name, call_stack_buf, CALL_STACK_SIZE);
        LOG("KPROBE:   stack trace: %s", call_stack_buf);
        put_cpu_ptr(cpu_call_stack);
    }

    if (wr->args.log_mode & CALL_LOG) {
        kprobe_log_entry entry;
        STRUCT_FROM_USER(&entry, data->log_entry_user_ptr);
        entry.return_value = regs_return_value(regs);
        STRUCT_TO_USER(&entry, data->log_entry_user_ptr);
    }

    return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static int sym_lookup(void) {
    // using kprobe to get the address of kallsyms_lookup_name which is not exported by the kernel anymore
    struct kretprobe kp = { 0 };
    kp.kp.symbol_name = "kallsyms_lookup_name";
    CHECK_ZERO(register_kretprobe(&kp), ERROR_GENERIC);
    _kallsyms_lookup_name = (void*)kp.kp.addr;
    unregister_kretprobe(&kp);

    // lookup other non-exported symbol addresses with kallsyms_lookup_name
    kaslr_base = _kallsyms_lookup_name("_text");
    _sprint_backtrace = (void*)_kallsyms_lookup_name("sprint_backtrace");
    _stack_trace_save_tsk_reliable = (void*)_kallsyms_lookup_name("stack_trace_save_tsk_reliable");
    _stack_trace_save_tsk = (void*)_kallsyms_lookup_name("stack_trace_save_tsk");
    return SUCCESS;
}

static int install_kprobe(kprobe_args* args, kretprobe_wrapper** wrapper) {
    kretprobe_wrapper* wr = kzalloc(sizeof(kretprobe_wrapper), GFP_KERNEL);
    *wrapper = wr;
    if (args->arg_count > 6)
        args->arg_count = 6;
    wr->args = *args;
    wr->kretprobe.handler = ret_handler;
    wr->kretprobe.entry_handler = entry_handler;
    wr->kretprobe.data_size = sizeof(struct kprobe_data);
    wr->kretprobe.maxactive = 20;
    wr->kretprobe.kp.symbol_name = wr->args.function_name;
    int res = CHECK_ZERO_NO_RET(register_kretprobe(&wr->kretprobe));
    if (res) return ERROR_GENERIC;
    LOG("KPROBE: %s: hook installed (addr=0x%llx, name=%pBb)", wr->args.function_name, (uint64_t)wr->kretprobe.kp.addr, wr->kretprobe.kp.addr);
    return SUCCESS;
}

static void remove_kprobe(kretprobe_wrapper* wr) {
    unregister_kretprobe(&wr->kretprobe);
    kfree(wr);
}

static noinline long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    kpwn_message msg;
    void* user_ptr = (void*) arg;

    uint name_idx = cmd - FIRST_CMD_ID;
    const char* cmd_name = 0 <= name_idx && name_idx < sizeof(cmd_names)/sizeof(cmd_names[0]) ? cmd_names[name_idx] : "INVALID";

    LOG("dev_ioctl, cmd=%s (0x%x), arg=%lx", cmd_name, cmd, arg);
    switch (cmd) {
        case ALLOC_BUFFER:
            long res = alloc_buffer(&msg, (void*)arg);
            if (res < 0)
                kfree(msg.kernel_ptr);
            return res;

        case KFREE:
            kfree((void*) arg);
            return SUCCESS;

        case KASLR_LEAK:
            STRUCT_TO_USER(&kaslr_base, user_ptr);
            return SUCCESS;

        case WIN_TARGET:
            won = 0;
            unsigned long win_target_addr = (unsigned long)&win_target;
            STRUCT_TO_USER(&win_target_addr, user_ptr);
            return SUCCESS;

        case RIP_CONTROL:
            rip_control_args rip_args;
            STRUCT_FROM_USER(&rip_args, user_ptr);
            rip_control_wrapper(&rip_args);
            return SUCCESS;

        case ARB_READ:
            STRUCT_FROM_USER(&msg, user_ptr);
            //LOG("ARB_READ: kernel=0x%llx, user=0x%llx, len=%llu", (uint64_t)msg.kernel_ptr, (uint64_t)msg.data, msg.length);
            DATA_TO_USER(msg.kernel_ptr, msg.data, msg.length);
            return SUCCESS;

        case ARB_WRITE:
            STRUCT_FROM_USER(&msg, user_ptr);
            DATA_FROM_USER(msg.kernel_ptr, msg.data, msg.length);
            return SUCCESS;

        case INSTALL_KPROBE:
            kprobe_args args;
            kretprobe_wrapper* wrapper_ptr;
            STRUCT_FROM_USER(&args, user_ptr);
            CHECK_ZERO(install_kprobe(&args, &wrapper_ptr), ERROR_GENERIC);
            args.installed_kprobe = wrapper_ptr; // TODO: replace with ID (idr_alloc, also cleanup when the device is closed)
            STRUCT_TO_USER(&args, user_ptr); // TODO: optimize this
            return SUCCESS;

        case REMOVE_KPROBE:
            // TODO: again, use ID instead, now blindly trust user-space to send a correct kernel ptr
            remove_kprobe(user_ptr);
            return SUCCESS;

        case PRINTK:
            char buf[512];
            STRING_FROM_USER(buf, user_ptr);
            printk(KERN_ERR "%s\n", buf);
            return SUCCESS;

        case SYM_ADDR:
            sym_addr sym_args;
            STRUCT_FROM_USER(&sym_args, user_ptr);
            sym_args.symbol_addr = _kallsyms_lookup_name(sym_args.symbol_name);
            if (!sym_args.symbol_addr)
                return -ERROR_UNKNOWN_SYMBOL;
            STRUCT_TO_USER(&sym_args, user_ptr);
            return SUCCESS;

        case GET_RIP_CONTROL_RECOVERY:
            uint64_t rip_recovery_addr = (uint64_t)&rip_control_recover;
            STRUCT_TO_USER(&rip_recovery_addr, user_ptr);
            return SUCCESS;

        case CHECK_WIN:
            long result = won ? SUCCESS : ERROR_GENERIC;
            won = 0;
            return result;

        default:
            return -ERROR_UNKNOWN_COMMAND;
    }
}

static int dev_open(struct inode *inode, struct file *file) {
    LOG("dev_open");
    return 0;
}

static int dev_close(struct inode *inode, struct file *file) {
    LOG("dev_close");
    return 0;
}

static struct file_operations dev_fops = {
    .owner          = THIS_MODULE,
    .read           = 0,
    .write          = 0,
    .open           = dev_open,
    .unlocked_ioctl = dev_ioctl,
    .release        = dev_close,
};

static int dev_no;
struct class *class;
struct device *device;

static int __init _module_init(void) {
    sym_lookup();

    int major_num;
    if ((major_num = register_chrdev(0, DEVICE_NAME, &dev_fops)) < 0) {
        LOG("register_chrdev failed with %d", major_num);
        return -EBUSY;
    }

    dev_no = MKDEV(major_num, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    if (IS_ERR(class = class_create(DEVICE_NAME))) {
#else
    if (IS_ERR(class = class_create(THIS_MODULE, DEVICE_NAME))) {
#endif
        LOG("class_create failed with %ld", PTR_ERR(class));
        unregister_chrdev_region(dev_no, 1);
        return -1;
    }

    if (IS_ERR(device = device_create(class, NULL, dev_no, NULL, DEVICE_NAME))) {
        LOG("device_create failed with %ld", PTR_ERR(device));
        class_destroy(class);
        unregister_chrdev_region(dev_no, 1);
        return -1;
    }

    LOG("module was successfully initialized.");
    return 0;
}

static void __exit _module_exit(void) {
    unregister_chrdev_region(dev_no, 1);
    LOG("module successfully exited.");
}

module_init(_module_init);
module_exit(_module_exit);