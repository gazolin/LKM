#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x141d70f7, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xb19e84a2, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0xba497f13, __VMLINUX_SYMBOL_STR(loops_per_jiffy) },
	{ 0xdcb0349b, __VMLINUX_SYMBOL_STR(sys_close) },
	{ 0xca1d5aed, __VMLINUX_SYMBOL_STR(fget) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xacf824c4, __VMLINUX_SYMBOL_STR(d_path) },
	{ 0xcda60f48, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4F298C9BFB28B0D9BECD4CD");
