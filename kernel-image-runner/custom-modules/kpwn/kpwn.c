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
#include <asm/setup.h>
#include "kpwn.h"
#include "utils.h"
#include "rip_control.h"

MODULE_LICENSE("GPL");

#define DEVICE_NAME "kpwn"

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
    printk(KERN_ERR "kpwn: win_target was called.\n\n!!! YOU WON !!! \n\n");
}

static noinline long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    kpwn_message msg;
    void* user_ptr = (void*) arg;

    printk(KERN_ERR "kpwn: dev_ioctl, cmd=%x, arg=%lx\n", cmd, arg);
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
            unsigned long kaslr_base = kallsyms_lookup_name("_text");
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

        default:
            return -ERROR_UNKNOWN_COMMAND;
    }
}

static int dev_open(struct inode *inode, struct file *file) {
    printk(KERN_ERR "kpwn: dev_open\n");
    return 0;
}

static int dev_close(struct inode *inode, struct file *file) {
    printk(KERN_ERR "kpwn: dev_close\n");
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
    int major_num;
    if ((major_num = register_chrdev(0, DEVICE_NAME, &dev_fops)) < 0) {
        printk(KERN_ERR "kpwn: register_chrdev failed with %d\n", major_num);
        return -EBUSY;
    }

    dev_no = MKDEV(major_num, 0);

    if (IS_ERR(class = class_create(THIS_MODULE, DEVICE_NAME))) {
        printk(KERN_ERR "kpwn: class_create failed with %ld\n", PTR_ERR(class));
        unregister_chrdev_region(dev_no, 1);
        return -1;
    }

    if (IS_ERR(device = device_create(class, NULL, dev_no, NULL, DEVICE_NAME))) {
        printk(KERN_ERR "kpwn: device_create failed with %ld\n", PTR_ERR(device));
        class_destroy(class);
        unregister_chrdev_region(dev_no, 1);
        return -1;
    }

    printk(KERN_ERR "kpwn: module was successfully initialized.\n");
    return 0;
}

static void __exit _module_exit(void) {
    unregister_chrdev_region(dev_no, 1);
    printk(KERN_ERR "kpwn: module successfully exited.\n");
}

module_init(_module_init);
module_exit(_module_exit);