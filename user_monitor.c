#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/in.h>

#define CR0_WP 0x00010000 
#define BUFLEN 128

static char msg[BUFLEN];
static int is_tcp = 0;
static int port = 0;
static struct in_addr ip;
static int last_sockfd = 0;

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*original_open_call)(const char *, int, int);
long (*original_read_call)(int, const void *, size_t);
long (*original_write_call)(int, const void *, size_t);
long (*original_connect_call)(int, const struct sockaddr *, int);
long (*original_bind_call)(int, const struct sockaddr *, int);
long (*original_listen_call)(int, int);
long (*original_mount_call)(const char *, const char *, const char *, unsigned long , const void *);


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
    printk(KERN_INFO "%s (pid:%d) is opening %s", filename, current->pid, d_path(&current->mm->exe_file->f_path, msg, BUFLEN));
    return original_open_call(filename, flags, mode);
}

int user_read(int fd, const void *buf, size_t count)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    const char * read_file = d_path(&(fget(fd)->f_path), msg, BUFLEN);

    printk(KERN_INFO "%s (pid:%d) is reading %d bytes from %s", read_file, current->pid, (int)count, exec_file);
    return original_read_call(fd, buf, count);
}

int user_write(int fd, const void *buf, size_t count)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    const char * write_file = d_path(&(fget(fd)->f_path), msg, BUFLEN);

    printk(KERN_INFO "%s (pid:%d) is writing %d butes to %s", write_file, current->pid, (int)count, exec_file);
    return original_write_call(fd, buf, count);
}

/* -------- end file monitoring --------- */

/* -------- socket monitoring --------- */

int user_connect(int sockfd, const struct sockaddr *addr, int addrLen)
{

    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    struct sockaddr_in * sina = (struct sockaddr_in *) addr;
    int port = ntohs(sina->sin_port);
    struct in_addr ip = sina->sin_addr;

    if (addr->sa_family == AF_INET) //TCP, UDP, etc.
    {
        printk(KERN_INFO "%s (pid:%d) recieved a connection from %pI4:%d\n", exec_file, current->pid, &ip, port);
    }

    return original_connect_call(sockfd, addr, addrLen);
}
int user_bind(int sockfd, const struct sockaddr *addr, int addrLen)
{
    struct sockaddr_in * sina = (struct sockaddr_in *) addr;

    //save to use when listen is called
    port = ntohs(sina->sin_port);
    ip = sina->sin_addr;
    last_sockfd = sockfd;

    if (addr->sa_family == AF_INET) //TCP, UDP, etc.
    {
        is_tcp = 1;
    }

    return original_bind_call(sockfd, addr, addrLen);
}
/* couldn't find ip and port directly, 
   will use sockfd to compare the bind syscall with the listen syscalls 
   and use the params from the bind action */

int user_listen(int sockfd, int backlog)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    if (sockfd == last_sockfd && is_tcp) //TCP, UDP, etc. also test the sockfd
    {
        printk(KERN_INFO "%s (pid:%d) is listening to %pI4:%d\n", exec_file, current->pid, &ip, port);
    }

    return original_listen_call(sockfd, backlog);
}

/* -------- end socket monitoring --------- */


/* --------- mount monitoring ----------*/

int user_mount (const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    printk(KERN_INFO "%s (pid:%d) mounted %s to %s using %s\n", exec_file, current->pid, source, target, filesystemtype);
    
    return original_mount_call(source, target, filesystemtype, mountflags, data);
}

/* -------- end mount monitoring --------*/

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

   original_connect_call = syscall_table[__NR_connect];
    syscall_table[__NR_connect] = user_connect;

    original_bind_call = syscall_table[__NR_bind];
    syscall_table[__NR_bind] = user_bind; 

    original_listen_call = syscall_table[__NR_listen];
    syscall_table[__NR_listen] = user_listen; 

    original_mount_call = syscall_table[__NR_mount];
    syscall_table[__NR_mount] = user_mount; 


    write_cr0(cr0);
  
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_INFO "byebye!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    syscall_table[__NR_open] = original_open_call;
    syscall_table[__NR_read] = original_read_call;
    syscall_table[__NR_write] = original_write_call;
    syscall_table[__NR_connect] = original_connect_call;
    syscall_table[__NR_bind] = original_bind_call;
    syscall_table[__NR_listen] = original_listen_call;
    syscall_table[__NR_mount] = original_mount_call;




        
    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);
