/*
 * 在console下可以:
 * 查看模块信息: modinfo hello.ko
 * 加载模块: lsmod hello.ko
 * 卸载模块: rmmod hello.ko
 * 查看printk输出的信息: tail /var/log/kern.log
 */
#include <linux/module.h>     /* 模块头文件，必不可少 */
#include <linux/kernel.h>     /* KERN_INFO在这里 */
#include <linux/init.h>       /* 使用的宏 */

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <linux/module.h>


MODULE_LICENSE("GPL");

MODULE_AUTHOR("cfycyf");

MODULE_DESCRIPTION("My First LKM hello!");

MODULE_VERSION("4.15");

static int __init hello_init(void)
{
	printk(KERN_INFO "Init Hello World\n");
	printk(KERN_INFO, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxLINUX_VERSION_CODE=%ld\n",LINUX_VERSION_CODE);
	return 0;
}
 
static void __exit hello_exit(void)
{
	printk(KERN_INFO "Exit to Hello\n");
}
 
module_init(hello_init);
module_exit(hello_exit);
