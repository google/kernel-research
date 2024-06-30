#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

MODULE_AUTHOR("");
MODULE_DESCRIPTION("");
MODULE_LICENSE("");

static int __init _module_init(void) {
    printk(KERN_ERR "helloworld module is loaded.\n");
    return 0;
}

static void __exit _module_exit(void) {
    printk(KERN_ERR "helloworld module is exiting...\n");
}

module_init(_module_init);
module_exit(_module_exit);

