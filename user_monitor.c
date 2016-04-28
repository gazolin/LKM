#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
//#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>

// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*orig_sys_setreuid)(uid_t ruid, uid_t euid);


unsigned long **find_sys_call_table()
{
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
             
        p = (unsigned long *) ptr;

        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    
    return NULL;
}

int user_monitor(uid_t ruid, uid_t euid)
{
    

    return orig_sys_setreuid(ruid, euid);
}

static int __init syscall_init(void)
{
    unsigned long cr0;

    printk(KERN_INFO "Let's do some magic!\n");

    syscall_table = (void **) find_sys_call_table();

    if (! syscall_table) {
        printk(KERN_INFO "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_INFO "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    printk(KERN_INFO "Houston! We have full write access to all pages. Proceeding...\n");
    orig_sys_setreuid = syscall_table[__NR_setreuid];
    syscall_table[__NR_setreuid] = user_monitor;

    write_cr0(cr0);
  
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_INFO "I hate you!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    syscall_table[__NR_setreuid] = orig_sys_setreuid;
        
    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);
