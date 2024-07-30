// Kernel module for youtubeUnblock.
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include "mangle.h"




static int __init ykb_init(void) {
	pr_info("youtubeUnblock kernel module started.\n");
	return 0;
}

static void __exit ykb_destroy(void) {
	pr_info("youtubeUnblock kernel module destroyed.\n");
}

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtube unblock");

module_init(ykb_init);
module_exit(ykb_destroy);
