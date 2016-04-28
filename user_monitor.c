#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
//#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>

#define CR0_WP 0x00010000 

static char msg[128];
static int len = 0;
static int len_check = 1;

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*original_call)(const char *, int, int);


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

/* -------- file monitoring --------- */
int user_open(const char *filename, int flags, int mode)
{
    printk(KERN_INFO "%s\n(pid:%d) is opening %s.\n ", filename, current->pid, d_path(&current->mm->exe_file->f_path, msg, 128));

    return original_call(filename, flags, mode);
}

int user_read(struct file *sp_file,char __user *buf, size_t size, loff_t *offset)
{

    if (len_check)
     len_check = 0;
    else 
    {
        len_check = 1;
        return 0;
    }

    printk(KERN_INFO "proc called read %d\n",size);
    copy_to_user(buf,msg,len);
    return len;
}

int user_write(struct file *sp_file, const char __user *buf, size_t size, loff_t *offset)
{

    printk(KERN_INFO "proc called write %d\n",size);
    len = size;
    copy_from_user(msg,buf,len);
    return len;
}

/* -------- end file monitoring --------- */

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

    original_call = syscall_table[__NR_open];
    syscall_table[__NR_open] = user_open;

    write_cr0(cr0);
  
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_INFO "I hate you!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    syscall_table[__NR_open] = original_call;
        
    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);
