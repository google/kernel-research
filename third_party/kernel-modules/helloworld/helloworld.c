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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");

static int __init _module_init(void) {
    printk(KERN_ERR "helloworld module is loaded.\n");
    return 0;
}

static void __exit _module_exit(void) {
    printk(KERN_ERR "helloworld module is exiting...\n");
}

module_init(_module_init);
module_exit(_module_exit);

