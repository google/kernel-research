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

static long alloc_buffer(kpwn_message* msg, void* user_ptr) {
    msg->kernel_ptr = 0;
    STRUCT_FROM_USER(msg, user_ptr);
    msg->kernel_ptr = CHECK_ALLOC(kmalloc(msg->length, msg->gfp_account ? GFP_KERNEL_ACCOUNT : GFP_KERNEL));
    if (msg->data)
        DATA_FROM_USER(msg->kernel_ptr, msg->data, msg->length);
    STRUCT_TO_USER(msg, user_ptr);
    return SUCCESS;
}

static void win_target(void) {
    LOG("win_target was called.\n\n!!! YOU WON !!! \n");
}

unsigned long kaslr_base = 0;

struct kprobe_data {
    ktime_t entry_stamp;
};

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

LIST_HEAD(kprobes);

typedef struct {
    struct list_head list;
    struct kretprobe kretprobe;
    kprobe_args args;
} kretprobe_wrapper;

DEFINE_PER_CPU(int, disabled);

#define GET_CPU_VAR(var_name) ({ typeof(var_name) __temp = get_cpu_var(var_name); put_cpu_var(var_name); __temp; })
#define SET_CPU_VAR(var_name, new_value) ({ get_cpu_var(var_name) = new_value; put_cpu_var(var_name); })

static int my_dump_stack(const char* hooked_func) {
    unsigned long stack_trace[32];
    char function_name[KSYM_NAME_LEN];
    char stack_trace_buf[512];
    int buf_idx = 0;
    // skip first 6 entries, they are:
    //   stack_trace_save_tsk_reliable+0x78/0xd0
    //   my_dump_stack.isra.0+0x3b/0xb0 [kpwn]
    //   entry_handler+0x98/0xb0 [kpwn]
    //   pre_handler_kretprobe+0x37/0x90
    //   kprobe_ftrace_handler+0x1a2/0x240
    //   0xffffffffc03db0dc   // optimized area(?)
    int len = CHECK_ALLOC(_stack_trace_save_tsk_reliable(current, stack_trace, ARRAY_SIZE(stack_trace)));
    for (int i = 6; i < len; i++) {
        _sprint_backtrace(function_name, stack_trace[i]);
        buf_idx += snprintf(&stack_trace_buf[buf_idx], ARRAY_SIZE(stack_trace_buf) - buf_idx, (buf_idx == 0 ? "%s" : " <- %s"), function_name);
    }
    LOG("KPROBE: %s: stack trace: %s", hooked_func, stack_trace_buf);
    return SUCCESS;
}

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kretprobe* rp = get_kretprobe(ri);
    kretprobe_wrapper* wr = container_of(rp, kretprobe_wrapper, kretprobe);

    // !current->mm - skipping kernel threads
    if (GET_CPU_VAR(disabled) || !current->mm || (wr->args.pid_filter != -1 && current->pid != wr->args.pid_filter))
        return 1;

    if (wr->args.log_mode & ENTRY) {
        LOG("KPROBE: %s: entry, rdi=0x%lx, rsi=0x%lx, rdx=0x%lx, rcx=0x%lx, r8=0x%lx, r9=0x%lx", rp->kp.symbol_name,
            regs->di, regs->si, regs->dx, regs->cx, regs->r8, regs->r9);
    }

    if (wr->args.log_mode & ENTRY_CALLSTACK) {
        my_dump_stack(rp->kp.symbol_name);
    }

    return 0;
}
NOKPROBE_SYMBOL(entry_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kretprobe* rp = get_kretprobe(ri);
    kretprobe_wrapper* wr = container_of(rp, kretprobe_wrapper, kretprobe);
    //struct kprobe_data *data = (struct kprobe_data *)ri->data;

    if (wr->args.log_mode & RETURN) {
        LOG("KPROBE: %s: returned 0x%lx", rp->kp.symbol_name, regs_return_value(regs));
    }

    if (wr->args.log_mode & RETURN_CALLSTACK) {
        my_dump_stack(rp->kp.symbol_name);
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
    return SUCCESS;
}

static int install_kprobe(const kprobe_args* args) {
    SET_CPU_VAR(disabled, 1);
    kretprobe_wrapper* wr = kzalloc(sizeof(kretprobe_wrapper), GFP_KERNEL);
    wr->args = *args;
    wr->kretprobe.handler = ret_handler;
    wr->kretprobe.entry_handler = entry_handler;
    wr->kretprobe.data_size = sizeof(struct kprobe_data);
    wr->kretprobe.maxactive = 20;
    wr->kretprobe.kp.symbol_name = wr->args.function_name;
    int res = CHECK_ZERO_NO_RET(register_kretprobe(&wr->kretprobe));
    SET_CPU_VAR(disabled, 0);
    if (res) return ERROR_GENERIC;
    LOG("KPROBE: %s: hook installed (addr=0x%llx, name=%pBb)", wr->args.function_name, (uint64_t)wr->kretprobe.kp.addr, wr->kretprobe.kp.addr);
    return SUCCESS;
}

static noinline long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    kpwn_message msg;
    void* user_ptr = (void*) arg;

    LOG("dev_ioctl, cmd=%x, arg=%lx", cmd, arg);
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
            unsigned long win_target_addr = (unsigned long)&win_target;
            STRUCT_TO_USER(&win_target_addr, user_ptr);
            return SUCCESS;

        case RIP_CONTROL:
            rip_control_args rip_args;
            STRUCT_FROM_USER(&rip_args, user_ptr);
            rip_control(&rip_args);
            return SUCCESS;

        case ARB_READ:
            STRUCT_FROM_USER(&msg, user_ptr);
            DATA_TO_USER(msg.kernel_ptr, msg.data, msg.length);
            return SUCCESS;

        case ARB_WRITE:
            STRUCT_FROM_USER(&msg, user_ptr);
            DATA_FROM_USER(msg.kernel_ptr, msg.data, msg.length);
            return SUCCESS;

        case INSTALL_KPROBE:
            kprobe_args args;
            STRUCT_FROM_USER(&args, user_ptr);
            CHECK_ZERO(install_kprobe(&args), ERROR_GENERIC);
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