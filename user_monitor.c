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
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>

#define CR0_WP 0x00010000 
#define BUFLEN 128

char msg[BUFLEN];
int is_tcp = 0, len = 0, port = 0, last_sockfd = 0, log_count = 0, i;
int len_check = 1;
int is_fileMon = 1;
int is_netMon = 1;
int is_mountMon = 1;
char log_text[10][BUFLEN];
char next_log[BUFLEN];
char fileMonState[BUFLEN];
char netMonState[BUFLEN];
char mountMonState[BUFLEN];
char log_cur_time[BUFLEN];
struct timeval t;
struct rtc_time tm;
unsigned long local;
struct in_addr ip;

MODULE_LICENSE("GPL");

//prototypes
void **syscall_table;
unsigned long **find_sys_call_table(void);
long (*original_open_call)(const char *, int, int);
long (*original_read_call)(int, const void *, size_t);
long (*original_write_call)(int, const void *, size_t);
long (*original_connect_call)(int, const struct sockaddr *, int);
long (*original_bind_call)(int, const struct sockaddr *, int);
long (*original_listen_call)(int, int);
long (*original_mount_call)(const char *, const char *, const char *, unsigned long , const void *);
void add_to_log(void);

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

/* -------- read and write from proc file ---------*/
ssize_t proc_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{

    copy_to_user(buf, msg, len);

    if (len_check)
        len_check = 0;
    else 
    {
        len_check = 1;
        return 0;
    }

    printk(KERN_INFO "KMonitor - Last Events:\n");

    for(i = 0; i < log_count && i < 10 ; i++)
    {
        printk(KERN_INFO "%s", log_text[i]);
    }

    if(is_fileMon)
        strcpy(fileMonState, "Enabled");
    else  
        strcpy(fileMonState,  "Disabled");

    if(is_netMon)
        strcpy(netMonState, "Enabled");
    else  
        strcpy(netMonState,  "Disabled");
    
    if(is_mountMon)
        strcpy(mountMonState, "Enabled");
    else  
        strcpy(mountMonState,  "Disabled");


    printk(KERN_INFO "File Monitoring - %s\nNetwork Monitoring - %s\nMount Monitoring - %s\n",fileMonState, netMonState, mountMonState);
    return len;
}

ssize_t proc_write(struct file *sp_file,const char __user *buf, size_t size, loff_t *offset)
{
    //change configuration values
    if (buf[7] == '0') is_netMon   = 0;
    if (buf[7] == '1') is_netMon   = 1;
    if (buf[8] == '0') is_fileMon  = 0;
    if (buf[8] == '1') is_fileMon  = 1;
    if (buf[9] == '0') is_mountMon = 0;
    if (buf[9] == '1') is_mountMon = 1;

    len = size;
    copy_from_user(msg, buf, len);
    return len;
}

static struct file_operations fops = {
.read = proc_read,
.write = proc_write,
};
/* -------- end read and write from proc file ---------*/

/* -------- file monitoring --------- */
int user_open(const char *filename, int flags, int mode)
{
    if (is_fileMon)
    {
        printk(KERN_INFO "%s (pid:%d) is opening %s\n", filename, current->pid, d_path(&current->mm->exe_file->f_path, msg, BUFLEN));
        snprintf(next_log, BUFLEN, "%s (pid:%d) is opening %s\n", filename, current->pid, d_path(&current->mm->exe_file->f_path, msg, BUFLEN));
        add_to_log();
    }

    return original_open_call(filename, flags, mode);
}

int user_read(int fd, const void *buf, size_t count)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    const char * read_file = d_path(&(fget(fd)->f_path), msg, BUFLEN);

    if (is_fileMon)
    {
        printk(KERN_INFO "%s (pid:%d) is reading %d bytes from %s\n", read_file, current->pid, (int)count, exec_file);
        snprintf(next_log, BUFLEN, "%s (pid:%d) is reading %d bytes from %s\n", read_file, current->pid, (int)count, exec_file);
        add_to_log();
    }

    return original_read_call(fd, buf, count);
}

int user_write(int fd, const void *buf, size_t count)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    const char * write_file = d_path(&(fget(fd)->f_path), msg, BUFLEN);

    if (is_fileMon)
    {
        printk(KERN_INFO "%s (pid:%d) is writing %d bytes to %s\n", write_file, current->pid, (int)count, exec_file);
        snprintf(next_log, BUFLEN, "%s (pid:%d) is writing %d bytes to %s\n", write_file, current->pid, (int)count, exec_file);
        add_to_log();
    }

    return original_write_call(fd, buf, count);
}
/* -------- end file monitoring --------- */

/* -------- socket monitoring --------- */
int user_connect(int sockfd, const struct sockaddr *addr, int addrLen)
{

    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);
    struct sockaddr_in * sina = (struct sockaddr_in *) addr;
    port = ntohs(sina->sin_port);
    ip = sina->sin_addr;

    if (addr->sa_family == AF_INET && is_netMon) //TCP, UDP, etc.
    {
        printk(KERN_INFO "%s (pid:%d) recieved a connection from %pI4:%d\n", exec_file, current->pid, &ip, port);
        snprintf(next_log, BUFLEN, "%s (pid:%d) recieved a connection from %pI4:%d\n", exec_file, current->pid, &ip, port);
        add_to_log();
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

    if (sockfd == last_sockfd && is_tcp && is_netMon) //TCP, UDP, etc. also test the sockfd
    {
        printk(KERN_INFO "%s (pid:%d) is listening to %pI4:%d\n", exec_file, current->pid, &ip, port);
        snprintf(next_log, BUFLEN, "%s (pid:%d) is listening to %pI4:%d\n", exec_file, current->pid, &ip, port);
        add_to_log();
    }

    return original_listen_call(sockfd, backlog);
}
/* -------- end socket monitoring --------- */

/* --------- mount monitoring ----------*/
int user_mount (const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
    const char * exec_file = d_path(&current->mm->exe_file->f_path, msg, BUFLEN);

    if (is_mountMon)
    {
        printk(KERN_INFO "%s (pid:%d) mounted %s to %s using %s\n", exec_file, current->pid, source, target, filesystemtype);
        snprintf(next_log, BUFLEN, "%s (pid:%d) mounted %s to %s using %s\n", exec_file, current->pid, source, target, filesystemtype);
        add_to_log();
    }
    
    return original_mount_call(source, target, filesystemtype, mountflags, data);
}
/* -------- end mount monitoring --------*/

/* -------- helper --------*/
void add_to_log()
{
    do_gettimeofday(&t);
    local = (u32)(t.tv_sec - (sys_tz.tz_minuteswest * 60));
    rtc_time_to_tm(local, &tm);

    snprintf(log_cur_time, BUFLEN, "%02d/%02d/%04d %02d:%02d:%02d ", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    strcat(log_cur_time, next_log);

    if(log_count < 9)
    {
        strcpy(log_text[log_count], log_cur_time);
        log_count ++;
    }
    else
    {
        for(i = 0; i < 9; i++)
        {
            strcpy(log_text[i], log_text[i + 1]);
        }

        strcpy(log_text[9], log_cur_time);
    }

    return;
}
/* -------- end helper --------*/

static int __init syscall_init(void)
{
    unsigned long cr0;

    /* ------- init proc file ------------*/
    printk(KERN_INFO "init KMonitor\n");
   
    if (! proc_create("KMonitor", 0666,NULL, &fops)) 
    {
        printk(KERN_INFO "ERROR! proc_create\n");
        remove_proc_entry("KMonitor", NULL);
        return -1;
    }
/* ------- end init proc file ------------*/

    syscall_table = (void **) find_sys_call_table();

    if (! syscall_table)
    {
        printk(KERN_INFO "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_INFO "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    printk(KERN_INFO "Changing syscalls.\n");


/* ------- change syscall table --------*/
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
/* ------- end change syscall table ------------*/

    write_cr0(cr0);
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;
    remove_proc_entry("KMonitor", NULL);

    printk(KERN_INFO "byebye!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    syscall_table[__NR_open] =    original_open_call;
    syscall_table[__NR_read] =    original_read_call;
    syscall_table[__NR_write] =   original_write_call;
    syscall_table[__NR_connect] = original_connect_call;
    syscall_table[__NR_bind] =    original_bind_call;
    syscall_table[__NR_listen] =  original_listen_call;
    syscall_table[__NR_mount] =   original_mount_call;

    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);
