#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
//#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/file.h>

#define CR0_WP 0x00010000 
#define BUFLEN 128

static char msg[BUFLEN];

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*original_open_call)(const char *, int, int);
long (*original_read_call)(int, const void *, size_t);
long (*original_write_call)(int, const void *, size_t);


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
    printk(KERN_INFO "%s (pid:%d) is opening %s\n", filename, current->pid, d_path(&current->mm->exe_file->f_path, msg, BUFLEN));
    return original_open_call(filename, flags, mode);
}

int user_read(int fd, const void *buf, size_t count)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    const char * read_file = d_path(&(fget(fd)->f_path), msg, BUFLEN);
    printk(KERN_INFO "%s (pid:%d) is reading %d bytes from %s\n", read_file, current->pid, (int)count, exec_file);
    return original_read_call(fd, buf, count);
}

int user_write(int fd, const void *buf, size_t count)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    const char * write_file = d_path(&(fget(fd)->f_path), msg, BUFLEN);
    printk(KERN_INFO "%s (pid:%d) is writing %d butes to %s\n", write_file, current->pid, (int)count, exec_file);
    return original_write_call(fd, buf, count);
}

/* -------- end file monitoring --------- */

static int __init syscall_init(void)
{
    unsigned long cr0;
    syscall_table = (void **) find_sys_call_table();

    if (! syscall_table) {
        printk(KERN_INFO "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_INFO "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    original_open_call = syscall_table[__NR_open];
    syscall_table[__NR_open] = user_open;

    original_read_call = syscall_table[__NR_read];
    syscall_table[__NR_read] = user_read;

    original_write_call = syscall_table[__NR_write];
    syscall_table[__NR_write] = user_write;

    write_cr0(cr0);
  
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_INFO "I hate you!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    syscall_table[__NR_open] = original_open_call;
    syscall_table[__NR_read] = original_read_call;
    syscall_table[__NR_write] = original_write_call;
        
    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);
